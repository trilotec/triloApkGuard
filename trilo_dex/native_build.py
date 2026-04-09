"""Native .so obfuscation generator and compiler.

Generates libtrilocfg.so with 8-layer obfuscation for Derive-B key storage.
"""

import os
import secrets
import struct
import subprocess
import tempfile
from pathlib import Path


# ─── String encryption table ─────────────────────────────────────────
# These are the strings the .so needs, stored as encrypted byte arrays.

REQUIRED_STRINGS = [
    "dlsym",
    "dlopen",
    "libdl.so",
    "/proc/self/status",
    "TracerPid:",
    "ro.hardware",
    "ro.product.device",
    "ro.debuggable",
    "qemu",
    "goldfish",
    "sdk",
    "generic",
    "/dev/qemu_pipe",
    "/dev/qemu_trace",
    "TracerPid",
    "libtrilocfg.so",
]


def _xor_encrypt(text: str, key: int) -> list[int]:
    """XOR encrypt a string, return byte list with null terminator."""
    return [(b ^ key) & 0xFF for b in text.encode("ascii")] + [0]


def _generate_obfuscated_c(derive_b: bytes) -> str:
    """Generate obfuscated C source code for key extraction.

    Args:
        derive_b: 16-byte key fragment to embed.

    Returns:
        C source code string.
    """

    # ── Layer 1: String encryption ──
    string_key = secrets.randbelow(256)
    enc_strings = {}
    for i, s in enumerate(REQUIRED_STRINGS):
        var_name = f"_s{i:02d}"
        enc_strings[var_name] = {
            "data": _xor_encrypt(s, string_key),
            "key": string_key,
            "var": var_name,
        }

    # ── Layer 3: Key fragmentation (16 bytes → 16 single-byte fragments) ──
    # Split into 16 bytes, each with different obfuscation
    fragments = []
    for i in range(16):
        byte_val = derive_b[i]
        method = i % 3  # 0=XOR, 1=ADD, 2=ROL

        if method == 0:  # XOR
            mask = secrets.randbelow(256)
            stored = byte_val ^ mask
            var_name = f"_f{i:02d}"
            fragments.append({
                "var": var_name,
                "stored": stored,
                "mask": mask,
                "method": "xor",
                "recover": f"{var_name} ^ 0x{mask:02x}",
            })
        elif method == 1:  # ADD
            offset = secrets.randbelow(256)
            stored = (byte_val + offset) & 0xFF
            var_name = f"_f{i:02d}"
            fragments.append({
                "var": var_name,
                "stored": stored,
                "mask": offset,
                "method": "add",
                "recover": f"(uint8_t)((uint16_t){var_name} - 0x{offset:02x})",
            })
        else:  # ROL (rotate left by 1-7)
            shift = (i % 7) + 1
            stored = ((byte_val << shift) | (byte_val >> (8 - shift))) & 0xFF
            var_name = f"_f{i:02d}"
            fragments.append({
                "var": var_name,
                "stored": stored,
                "mask": shift,
                "method": "rol",
                "recover": f"(uint8_t)(({var_name} >> {shift}) | ({var_name} << {8 - shift}))",
            })

    # Random permutation for reassembly order
    permutation = list(range(16))
    secrets.SystemRandom().shuffle(permutation)

    # ── Checksum for integrity validation ──
    expected_checksum = 0
    for b in derive_b:
        expected_checksum ^= b

    # ── Generate C source ──
    lines = []
    lines.append("#include <stdint.h>")
    lines.append("#include <string.h>")
    lines.append("#include <stdlib.h>")
    lines.append("#include <time.h>")
    lines.append("#include <unistd.h>")
    lines.append("#include <jni.h>")
    lines.append("")
    # JNI macros
    lines.append("#ifndef JNIEXPORT")
    lines.append("#define JNIEXPORT __attribute__((visibility(\"default\")))")
    lines.append("#endif")
    lines.append("#ifndef JNICALL")
    lines.append("#define JNICALL")
    lines.append("#endif")
    lines.append("")

    # JNI types (minimal, avoids jni.h to reduce symbol exposure)
    # jni.h defines all JNI types, no manual typedefs needed

    # ── Layer 1: Encrypted strings ──
    lines.append("/* Layer 1: Encrypted strings */")
    for info in enc_strings.values():
        data_str = ", ".join(f"0x{b:02x}" for b in info["data"])
        lines.append(f"static const uint8_t {info['var']}[] = {{{data_str}}};")
    lines.append(f"static const int _str_key = 0x{string_key:02x};")
    lines.append("")

    # ── Layer 3: Key fragments ──
    lines.append("/* Layer 3: Key fragments */")
    for frag in fragments:
        lines.append(f"static const uint8_t {frag['var']} = 0x{frag['stored']:02x};")
    lines.append("")

    # ── Helper: string decryption ──
    lines.append("static void _dec_str(char *out, const uint8_t *enc, int key) {")
    lines.append("    for (int i = 0; enc[i]; i++) out[i] = enc[i] ^ key;")
    lines.append("}")
    lines.append("")

    # ── Helper: wipe memory ──
    lines.append("static void _wipe(void *p, int len) {")
    lines.append("    volatile uint8_t *v = (uint8_t*)p;")
    lines.append("    for (int i = 0; i < len; i++) v[i] = 0;")
    lines.append("}")
    lines.append("")

    # ── Layer 5: Anti-debug ──
    lines.append("/* Layer 5: Anti-debug */")
    lines.append("static int _check_debug(void) {")
    lines.append("    char path[64];")
    lines.append("    _dec_str(path, _s04, _str_key);  /* \"/proc/self/status\" */")

    # TracerPid check
    lines.append("    FILE *fp = fopen(path, \"r\");")
    lines.append("    if (fp) {")
    lines.append("        char line[256];")
    lines.append("        _dec_str(path, _s05, _str_key);  /* \"TracerPid:\" */")
    lines.append("        int tlen = strlen(path);")
    lines.append("        while (fgets(line, sizeof(line), fp)) {")
    lines.append("            if (strncmp(line, path, tlen) == 0) {")
    lines.append("                int pid = atoi(line + tlen);")
    lines.append("                fclose(fp);")
    lines.append("                _wipe(line, sizeof(line));")
    lines.append("                if (pid != 0) return 1;")
    lines.append("            }")
    lines.append("        }")
    lines.append("        fclose(fp);")
    lines.append("    }")

    # ptrace check (syscall directly to avoid symbol)
    lines.append("    long ret = syscall(101, 0, 0, 0, 0);  /* PTRACE_TRACEME */")
    lines.append("    if (ret == 0) {")
    lines.append("        syscall(101, 1, getpid(), 0, 0);  /* PTRACE_DETACH */")
    lines.append("    } else {")
    lines.append("        return 1;")
    lines.append("    }")

    lines.append("    return 0;")
    lines.append("}")
    lines.append("")

    # ── Layer 6: Anti-emulator (simplified) ──
    lines.append("/* Layer 6: Anti-emulator (property check) */")
    lines.append("static int _check_emulator(void) {")
    lines.append("    /* Read ro.hardware via __system_property_get */")
    lines.append("    /* Simplified: check /proc/cpuinfo for qemu */")
    lines.append("    FILE *fp = fopen(\"/proc/cpuinfo\", \"r\");")
    lines.append("    if (fp) {")
    lines.append("        char buf[512];")
    lines.append("        int found = 0;")
    lines.append("        while (fgets(buf, sizeof(buf), fp)) {")
    lines.append("            if (strstr(buf, \"qemu\") || strstr(buf, \"goldfish\")) {")
    lines.append("                found = 1; break;")
    lines.append("            }")
    lines.append("        }")
    lines.append("        fclose(fp);")
    lines.append("        _wipe(buf, sizeof(buf));")
    lines.append("        if (found) return 1;")
    lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    lines.append("")

    # ── Layer 8: Timing check ──
    lines.append("/* Layer 8: Timing detection */")
    lines.append("static int _check_timing(void) {")
    lines.append("    struct timespec t1, t2;")
    lines.append("    clock_gettime(CLOCK_MONOTONIC, &t1);")
    lines.append("    /* Busy work to create timing baseline */")
    lines.append("    volatile long s = 0;")
    lines.append("    for (volatile long i = 0; i < 10000; i++) s += i;")
    lines.append("    clock_gettime(CLOCK_MONOTONIC, &t2);")
    lines.append("    long delta = (t2.tv_sec - t1.tv_sec) * 1000000 +")
    lines.append("                 (t2.tv_nsec - t1.tv_nsec) / 1000;")
    lines.append("    /* If >10ms, likely being debugged */")
    lines.append("    return delta > 10000 ? 1 : 0;")
    lines.append("}")
    lines.append("")

    # ── Fake key generator ──
    lines.append("static void _fake_key(uint8_t *out) {")
    lines.append("    struct timespec ts;")
    lines.append("    clock_gettime(CLOCK_MONOTONIC, &ts);")
    lines.append("    for (int i = 0; i < 16; i++)")
    lines.append("        out[i] = (uint8_t)((ts.tv_nsec >> (i * 4)) & 0xff);")
    lines.append("}")
    lines.append("")

    # ── Junk code function ──
    junk_func_name = f"_j{secrets.randbelow(0xFFFF):04x}"
    lines.append(f"static void {junk_func_name}(void) {{")
    lines.append("    volatile long s = 0;")
    lines.append("    for (volatile long i = 0; i < 5000; i++)")
    lines.append("        s = (s * 1103515245 + 12345) & 0x7fffffff;")
    lines.append("}")
    lines.append("")

    # ── Opaque predicate ──
    opaque_func = f"_p{secrets.randbelow(0xFFFF):04x}"
    lines.append(f"static int {opaque_func}(void) {{")
    lines.append("    volatile unsigned int x = 0x9E3779B9U;")
    lines.append("    x ^= x << 13; x ^= x >> 17; x ^= x << 5;")
    lines.append("    return (int)(x & 1);")
    lines.append("}")
    lines.append("")

    # JNI: getKeyPart (Layer 4: control flow flattening)
    lines.append("/* JNI: getKeyPart - returns 16-byte Derive-B */")
    lines.append("JNIEXPORT jbyteArray JNICALL")
    lines.append("Java_com_trilo_stub_KeyProvider_getKeyPart(JNIEnv *env, jclass clazz) {")

    lines.append("    int state = 100;")
    lines.append("    uint8_t key[16];")
    lines.append("    int is_debug = 0;")
    lines.append("")
    lines.append("    while (state != 0) {")
    lines.append("        switch (state) {")

    # State 100: Anti-debug check
    lines.append("            case 100:")
    lines.append("                if (_check_debug()) { state = 900; break; }")
    lines.append(f"                if (!{opaque_func}()) {{ state = 900; break; }}")
    lines.append("                state = 200; break;")

    # State 200: Anti-emulator check
    lines.append("            case 200:")
    lines.append("                if (_check_emulator()) { state = 900; break; }")
    lines.append(f"                {junk_func_name}();")
    lines.append("                state = 300; break;")

    # State 300: Timing check
    lines.append("            case 300:")
    lines.append("                if (_check_timing()) { state = 900; break; }")
    lines.append("                state = 400; break;")

    # State 400: Reassemble key fragments (in shuffled order)
    lines.append("            case 400:")
    for i, idx in enumerate(permutation):
        frag = fragments[idx]
        lines.append(f"                key[{i}] = {frag['recover']};")
    lines.append("                state = 500; break;")

    # State 500: Checksum validation
    lines.append("            case 500: {")
    lines.append("                uint8_t cs = 0;")
    lines.append("                for (int i = 0; i < 16; i++) cs ^= key[i];")
    hex_ck = f"0x{expected_checksum:02x}"
    lines.append(f"                if (cs != {hex_ck}) {{ state = 900; break; }}")
    lines.append("                state = 600; break;")
    lines.append("            }")

    # State 600: Return key
    lines.append("            case 600: {")
    lines.append("                jbyteArray arr = (*env)->NewByteArray(env, 16);")
    lines.append("                (*env)->SetByteArrayRegion(env, arr, 0, 16, (const jbyte*)key);")
    lines.append("                _wipe(key, 16);")
    lines.append("                return arr;")
    lines.append("            }")

    # State 900: Fake key path
    lines.append("            case 900:")
    lines.append("                _fake_key(key);")
    lines.append("                state = 600; break;")

    lines.append("            default: state = 0; break;")
    lines.append("        }")
    lines.append("    }")
    lines.append("    return NULL;")
    lines.append("}")

    return "\n".join(lines)


def compile_native_lib(
    derive_b: bytes,
    output_path: str,
    ndk_clang: str | None = None,
    abi: str = "arm64-v8a",
) -> str:
    """Generate obfuscated C code and compile to .so.

    Args:
        derive_b: 16-byte key fragment.
        output_path: Where to write the .so file.
        ndk_clang: Path to NDK clang. If None, uses 'clang' from PATH.
        abi: Target ABI (arm64-v8a, armeabi-v7a, x86_64, x86).

    Returns:
        Path to compiled .so file.
    """
    if len(derive_b) != 16:
        raise ValueError(f"derive_b must be 16 bytes, got {len(derive_b)}")

    # Generate C source
    c_source = _generate_obfuscated_c(derive_b)

    # Write to temp file
    with tempfile.NamedTemporaryFile(suffix=".c", delete=False, mode="w") as f:
        f.write(c_source)
        c_path = f.name

    try:
        # Determine target triple
        abi_map = {
            "arm64-v8a": "aarch64-linux-android26",
            "armeabi-v7a": "armv7a-linux-androideabi26",
            "x86_64": "x86_64-linux-android26",
            "x86": "i686-linux-android26",
        }
        target = abi_map.get(abi, abi_map["arm64-v8a"])

        compiler = ndk_clang or "clang"
        cmd = [
            compiler,
            "-target", target,
            "-c", c_path,
            "-o", c_path + ".o",
            "-Os",
            "-fno-stack-protector",
            "-fvisibility=hidden",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wno-unused-value",
        ]

        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"clang compile failed:\n{result.stderr}"
            )

        # Link as shared library
        cmd_link = [
            compiler,
            "-target", target,
            "-shared",
            c_path + ".o",
            "-o", output_path,
            "-Wl,--strip-all",
            "-Wl,--gc-sections",
            "-llog",
        ]

        subprocess.run(cmd_link, check=True, capture_output=True)

    finally:
        # Cleanup temp files
        for p in [c_path, c_path + ".o"]:
            if os.path.exists(p):
                os.unlink(p)

    return output_path


def generate_derive_b() -> bytes:
    """Generate a random 16-byte Derive-B key fragment."""
    return secrets.token_bytes(16)
