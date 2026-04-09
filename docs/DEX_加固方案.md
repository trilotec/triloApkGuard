# TriloDexPack - DEX 加固方案

## 1. 概述

### 1.1 目标

构建一个 DEX 加固工具，保护 Android APK 中的 DEX 字节码不被静态分析。通过加密 + 内存加载的方式，使 DEX 文件在 APK 中以密文形式存在，仅在运行时解密到内存中执行，避免 DEX 落盘。

### 1.2 项目阶段

| 阶段 | 目标 |
|---|---|
| **阶段一（当前）** | DEX 加固 CLI 本地工具 |
| **阶段二（规划）** | SaaS 平台（Web 端上传 APK → 服务端加固 → 下载加固后 APK） |

---

## 2. 保护方案设计

### 2.1 整体架构

```
┌─────────────────────────────────────────────────────────────┐
│                     加固工具 (CLI)                           │
├─────────────────────────────────────────────────────────────┤
│  输入: app.apk                                               │
│    │                                                         │
│    ├─ 1. 解析 APK → 提取 classes*.dex                        │
│    ├─ 2. triloSec (AES-256-GCM) 加密 DEX → assets/encrypted_classes.dat │
│    ├─ 3. 编译 StubApplication.smali → stub.dex               │
│    ├─ 4. 注入 stub.dex 为新的 classes.dex                    │
│    ├─ 5. 修改 AndroidManifest.xml → 替换 Application 入口     │
│    ├─ 6. 重新打包 APK (ZIP)                                  │
│    ├─ 7. zipalign 对齐                                       │
│    ├─ 8. apksigner 签名                                      │
│    │                                                         │
│    └─ 输出: app_protected.apk                                │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 triloSec 加密算法

**triloSec** 是本项目的加密保护方案名称，核心使用 **AES-256-GCM** 算法。

#### 2.2.1 为什么用 GCM 而不是 CBC

| 对比 | CBC | GCM |
|---|---|---|
| 机密性 | 加密保护 | 加密保护 |
| 完整性认证 | **无** | **有 (内置 16B auth tag)** |
| 篡改检测 | 无法检测，输出垃圾数据 | 校验失败抛 AEADBadTagException |
| 并行加密 | 不行 | 可以 |
| 填充 | 需要 PKCS7 padding | 不需要 (流模式) |
| 业界标准 | 逐步淘汰 | TLS 1.3 强制使用 |

GCM 的"认证"含义: 加密时生成一个 16 字节的 auth tag 附加到密文后。解密时自动校验 tag，如果密文被修改（哪怕 1 字节），tag 不匹配直接报错。CBC 没有这个能力。

#### 2.2.2 加密参数

| 项目 | 值 |
|---|---|
| 算法 | AES-256-GCM (AEAD) |
| 密钥 | 256 bit (32 bytes) |
| Nonce | 96 bit (12 bytes)，每文件随机生成 |
| 认证标签 | 128 bit (16 bytes) |
| 输出格式 | `[12B nonce][16B auth tag][密文]` |
| 存储位置 | APK 的 `assets/` 目录下，文件名 `encrypted_classes.dat`、`encrypted_classes2.dat` 等 |

#### 2.2.3 输出文件格式

```
偏移      大小          内容
0x00      12 bytes      AES-GCM nonce (96-bit, 随机)
0x0C      16 bytes      GCM authentication tag
0x1C      N bytes       加密后的 DEX 密文 (无填充)
```

#### 2.2.4 .dexmeta 元数据

```json
{
  "version": 1,
  "algorithm": "triloSec-v1",
  "files": [
    {
      "encrypted_name": "encrypted_classes.dat",
      "original_name": "classes.dex",
      "nonce_hex": "a1b2c3d4e5f6a1b2c3d4e5f6",
      "gcm_tag_hex": "1a2b3c4d5e6f...",
      "original_size": 1234567
    }
  ]
}
```
- 魔数 "TRL0" 标识为 triloSec 加密文件

**.dexmeta 格式：**

```json
{
  "version": 1,
  "algorithm": "triloSec-v1",
  "sbox": "a3f2b1c0d4e5...",
  "sbox_hash": "1a2b3c4d...",
  "files": [
    {
      "encrypted_name": "encrypted_classes.dat",
      "original_name": "classes.dex",
      "nonce_hex": "a1b2c3d4e5f6a1b2c3d4e5f6",
      "gcm_tag_hex": "1a2b3c4d5e6f...",
      "original_size": 1234567
    }
  ]
}
```

### 2.3 密钥存储方案

#### 2.3.1 各存储方案对比

| 方案 | 安全性 | 兼容性 | 实现成本 | 评价 |
|---|---|---|---|---|
| 仅放 .so | 中 | 高 | 低 | `strings` 或反汇编可直接拿到，单点 |
| 仅放资源文件 | 低 | 高 | 极低 | `apktool d` 就能看到，等于明文 |
| 仅放 assets | 低 | 高 | 低 | 同上，资源目录谁都能翻 |
| TrustZone (TEE) | 极高 | 低 | 高 | 最安全但问题太多：不同厂商 TEE 实现不同、需要用户授权、部分设备不支持、SaaS 无法预置密钥 |
| **拆分多源 (本方案)** | **中高** | **高** | **中** | **最佳平衡** |

> **TrustZone 不适用的原因：** TEE (KeyStore/KeyAttestation) 需要应用先在目标设备上运行并完成密钥注册，SaaS 加固工具在云端无法预置密钥到用户设备的 TEE 中。且不同芯片厂商 (Qualcomm TEE、Samsung Knox、Huawei TEE) 实现差异大。TEE 方案留作 V3 可选增强。

#### 2.3.2 三源派生方案

triloSec 采用 **三源 XOR 密钥派生** 策略。Master Key 不存在于任何单一位置，运行时从三个独立来源组合还原。

```
                    Master Key (32 bytes)
                           ▲
                    ════ XOR ════
                    ▲           ▲           ▲
               Derive-A    Derive-B    Derive-C
              (16 bytes)  (16 bytes)  (16 bytes)
                    │           │           │
             APK 自身特征   .so 深度混淆   资源文件
             (不可变属性)  (核心防护层)   (辅助源)
```

**为什么用 XOR 而不是拼接：** 每个源都是 16 bytes，XOR 后每个 bit 都依赖三个输入。单独拿到任何一个源都无法推断其他源，也无法还原密钥。

#### 2.3.3 Derive-A: APK 特征派生

**存储位置:** 不存储，运行时计算

```
Derive-A = SHA-256(packageName + "|" + minSdk + "|" + targetSdk + "|" + firstCertHash)[0:16]
```

| 输入 | 获取方式 | 安全作用 |
|---|---|---|
| packageName | `Context.getPackageName()` | 改包名 → Derive-A 变化 → 密钥错误 |
| minSdk | AndroidManifest.xml 中读取 | 修改 manifest 属性 → 密钥错误 |
| targetSdk | AndroidManifest.xml 中读取 | 同上 |
| firstCertHash | `PackageManager` 获取签名证书 SHA-256 | **换签名 = 密钥错误**，防重打包 |

**优势：** 这些信息本身就是 APK 的固有属性，不需要额外存储任何东西。攻击者即使拿到 Derive-B 和 Derive-C，只要不知道原始 APK 的包名/签名，就无法还原密钥。

#### 2.3.4 Derive-B: .so 深度混淆 (核心防护层)

**存储位置:** `lib/arm64-v8a/libtrilocfg.so` (及其他 ABI)

Derive-B 是最难提取的部分。单纯 XOR mask + junk code 用 Ghidra 打开后很容易被自动化分析。triloSec 采用 **8 层防护** 的 .so 混淆体系:

```
.so 防护体系:
┌─────────────────────────────────────────────┐
│ Layer 1: 字符串加密                            │  所有字符串常量加密存储
│   - 编译时用 XOR 加密每个字符串               │  strings 命令无输出
│   - 运行时按需解密到栈上, 用完立即覆写         │  内存中也只在需要时短暂存在
├─────────────────────────────────────────────┤
│ Layer 2: 动态符号解析                          │  不依赖静态 import table
│   - 所有系统调用通过 dlopen + dlsym 动态解析   │  Ghidra import 表为空
│   - 函数名也加密存储                           │  无法从符号名推断用途
│   - 缓存 dlsym 结果避免重复调用                │
├─────────────────────────────────────────────┤
│ Layer 3: 密钥深度分片                          │  16 字节 key 碎片化存储
│   - 拆为 16 × 1-byte 碎片                    │  每个字节独立混淆
│   - 碎片散落在 16+ 个不同函数中                │  无单一函数包含完整 key
│   - 碎片使用不同的混淆算法                      │  XOR/ADD/ROL 混合
│   - 重组顺序打乱 (按随机 permutation)          │  不能按内存顺序读取
├─────────────────────────────────────────────┤
│ Layer 4: 控制流平坦化                          │  消除线性代码结构
│   - switch dispatcher 模式                    │  所有逻辑变成状态机
│   - 嵌套子 dispatcher                         │  多层状态机嵌套
│   - bogus state (永远不执行的分支)             │  增加 CFG 复杂度
├─────────────────────────────────────────────┤
│ Layer 5: 反调试                                │  运行时检测调试环境
│   - ptrace(PTRACE_TRACEME) 自附加             │  阻止 gdb/IDA 附加
│   - 检查 /proc/self/status (TracerPid)        │  检测已附加的调试器
│   - 检查 android:debuggable                   │  检测调试模式 APK
│   - 检测到调试 → 返回假 key                    │  不崩溃, 默默返回错误数据
├─────────────────────────────────────────────┤
│ Layer 6: 反模拟器                              │  检测是否运行在模拟器中
│   - 读取 /proc/cpuinfo (检查 qemu 特征)        │  检测 QEMU
│   - 检查 ro.hardware / ro.product.device       │  检测通用模拟器名称
│   - 检查特殊文件 (/dev/qemu_pipe 等)           │  模拟器特有设备节点
│   - 检测到模拟器 → 静默返回假 key               │
├─────────────────────────────────────────────┤
│ Layer 7: 代码完整性校验                         │  检测 .so 自身是否被篡改
│   - 计算 .text 段 CRC32                       │  对比编译时嵌入的预期值
│   - 校验 JNI 函数体 hash                       │  检测 patch/hook
│   - 校验失败 → 返回假 key (不崩溃)              │
├─────────────────────────────────────────────┤
│ Layer 8: 时序检测                               │  检测执行时间异常
│   - 记录关键函数执行耗时                        │  调试时耗时显著增加
│   - clock_gettime 多点采样                     │  多点检测防绕过
│   - 耗时超标 → 判定被调试 → 返回假 key           │
└─────────────────────────────────────────────┘
```

#### 2.3.4.1 字符串加密 (Layer 1)

所有字符串不直接出现在二进制中，而是编译时 XOR 加密:

```c
// 源码中看不到 "dlsym"、"libdl.so"、"/proc/self/status" 等字符串
// 存储的是加密后的字节:
static const uint8_t _s0[] = { 0x7A, 0x66, 0x63, 0x70, 0x7E, 0x00 };  // "dlsym" ^ 0x13
static const uint8_t _s1[] = { 0x5E, 0x6B, 0x60, 0x00 };              // "lib" ^ 0x31

// 运行时解密到栈上, 用完覆写:
#define DEC_STR(buf, enc, key) do { \
    for (int _i = 0; enc[_i]; _i++) buf[_i] = enc[_i] ^ key; \
    buf[sizeof(enc)-1] = 0; \
} while(0)

// 使用后立即覆写栈内存:
volatile char *vp = buf;
for (int i = 0; i < sizeof(buf); i++) vp[i] = 0;
```

**效果:** `strings libtrilocfg.so | grep -i dlsym` 无任何输出。

#### 2.3.4.2 动态符号解析 (Layer 2)

不用 `#include <jni.h>` 的方式静态链接 JNI 函数，而是全部通过 dlopen/dlsym:

```c
// 不使用: #include <dlfcn.h>
// 而是: 运行时动态加载 libdl.so

typedef void* (*dlopen_fn)(const char*, int);
typedef void* (*dlsym_fn)(void*, const char*);

// 动态获取 dlopen/dlsym 本身
// 通过 linker 提供的 __libc_dlopen_mode (Android 特有)
// 或者直接从 memory 中解析 link_map

// JNI_OnLoad 时初始化:
static dlopen_fn g_dlopen;
static dlsym_fn g_dlsym;

void init_symbols() {
    char lib[32]; DEC_STR(lib, _enc_libdl, 0x42);
    g_dlopen = (dlopen_fn)_real_dlopen(lib, RTLD_NOW);

    char sym[32]; DEC_STR(sym, _enc_dlsym, 0x42);
    g_dlsym = (dlsym_fn)g_dlsym_internal(g_dlopen, sym);
}

// 之后所有系统调用:
// 如 fgets → 动态解析 → 调用 → 覆写字符串
```

**效果:** Ghidra/IDA 的 import 表中没有 `dlopen`、`dlsym`、`fopen`、`ptrace` 等函数名。逆向者必须执行到运行时才能看到实际调用。

#### 2.3.4.3 密钥分片 (Layer 3)

不是简单的 8 × 4-byte 碎片，而是 16 × 1-byte，每个用不同方式混淆:

```c
// 16 个字节碎片散落在不同函数中, 每个用不同的混淆方式:

// 碎片 0-5: XOR 混淆
static const uint8_t _f0 = key[0] ^ 0x37;
static const uint8_t _f1 = key[1] ^ 0xA5;

// 碎片 6-10: ADD 混淆
static const uint8_t _f6 = (key[6] + 0x4B) & 0xFF;

// 碎片 11-15: ROL (循环左移) 混淆
static const uint8_t _f11 = ROL8(key[11], 3);

// 重组时按随机顺序 (permutation):
int order[] = { 3, 11, 7, 0, 14, 5, 9, 1, 12, 6, 15, 2, 8, 13, 4, 10 };
for (int i = 0; i < 16; i++) {
    raw_key[i] = recover(order[i]);  // 每个用对应的逆操作
}
```

**效果:** 即使找到所有碎片, 也不知道每个碎片用的什么混淆方式, 更不知道重组顺序。

#### 2.3.4.4 控制流平坦化 (Layer 4)

将线性代码变成 switch 状态机, 消除可读的控制流:

```c
void JNI_getKeyPart(JNIEnv* env, jclass clazz) {
    int state = 100;
    uint32_t ctx[16];  // 状态变量

    while (state != 0) {
        switch (state) {
            case 100:  // 反调试检查
                if (check_debugger()) { state = 900; break; }  // 假 key 路径
                state = 200; break;

            case 200:  // 完整性校验
                if (!verify_integrity()) { state = 900; break; }
                state = 300; break;

            case 300: ctx[0] = get_fragment_3(); state = 301; break;
            case 301: ctx[1] = get_fragment_11(); state = 302; break;
            // ... 16 个碎片依次获取, 顺序是随机的

            case 400:  // 重组 key
                reassemble(ctx);
                state = 500; break;

            case 500:  // 返回结果
                return_jbytearray(env, ctx);
                state = 0; break;

            // 假 key 路径 (bogus states)
            case 900: gen_fake_key(ctx); state = 500; break;
            case 901: /* 永远不执行 */ gen_fake_key(ctx); state = 0; break;

            default: state = 0; break;  // 永远不会到 0
        }
    }
}
```

**效果:** Ghidra 的 CFG (控制流图) 变成一个大 switch，无法看出真正的执行顺序。

#### 2.3.4.5 反调试 (Layer 5)

```c
int check_debugger() {
    // 方法 1: ptrace 自附加
    long ret = syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
    if (ret < 0) return 1;  // 已被调试器附加
    syscall(SYS_ptrace, PTRACE_DETACH, getpid(), 0, 0);

    // 方法 2: 检查 TracerPid
    char path[64];
    build_path(path, _enc_proc_status, 0x2A);  // 加密字符串
    FILE *fp = open_file(path);
    // 读取 TracerPid 行, 非 0 则被调试
    int tracer_pid = parse_tracer_pid(fp);
    close_and_wipe(fp);
    if (tracer_pid != 0) return 1;

    // 方法 3: 检查 debuggable 标志
    if (is_debuggable()) return 1;

    return 0;
}
```

#### 2.3.4.6 代码完整性校验 (Layer 7)

```c
int verify_integrity() {
    // 1. 读取自身 ELF 文件的 .text 段
    ElfW(Addr) base = get_library_base();
    uint32_t crc = crc32_compute(text_start, text_size);

    // 2. 对比编译时嵌入的预期值
    if (crc != EXPECTED_TEXT_CRC) return 0;

    // 3. 校验 JNI 函数体 hash
    uint8_t hash[32];
    sha256_compute((uint8_t*)JNI_getKeyPart, FUNC_SIZE, hash);
    if (!memcmp(hash, EXPECTED_FUNC_HASH, 32)) return 0;

    return 1;
}
```

#### 2.3.4.7 .so 混淆生成流程

```
Python (native_build.py)
    │
    ├─ 输入: Derive-B (16 bytes)
    │
    ├─ 1. 生成字符串加密表 (所有常量字符串 → XOR 加密)
    ├─ 2. 生成密钥分片 (16 bytes → 16 碎片, 随机混淆方式)
    ├─ 3. 生成控制流平坦化代码 (switch 状态机)
    ├─ 4. 注入反调试代码 (ptrace + TracerPid + debuggable)
    ├─ 5. 注入反模拟器代码 (QEMU 检测)
    ├─ 6. 注入完整性校验 (CRC32 of .text)
    ├─ 7. 注入时序检测 (clock_gettime 多点采样)
    ├─ 8. 生成 C 源码 → trilocfg.c
    │
    └─ NDK clang 编译:
         - 编译选项: -Os -fno-stack-protector -fvisibility=hidden
         - 链接选项: -Wl,--strip-all (剥离符号表)
         - 输出: libtrilocfg.so
```

#### 2.3.4.8 版本差异

| 保护手段 | 开源版 V1 | SaaS V2 |
|---|---|---|
| 字符串加密 | ✓ (简单 XOR) | ✓ (多轮 + 运行时解密) |
| 动态符号解析 | ✓ (dlopen/dlsym) | ✓ + PLT GOT Hook 检测 |
| 密钥分片 | 16 碎片 | 32 碎片 + 动态重组 |
| 控制流平坦化 | 单层 switch | 多层嵌套 switch |
| 反调试 | ptrace + TracerPid | + timing + 断点检测 |
| 反模拟器 | 基础 QEMU 检测 | + root 检测 +  Frida 检测 |
| 完整性校验 | .text CRC32 | + 内存扫描 + hook 检测 |
| 时序检测 | ✓ (2 点采样) | ✓ (5+ 点采样 + 自适应阈值) |

#### 2.3.5 Derive-C: 资源文件

**存储位置:** `res/raw/trilodata.bin`

- 16 字节数据，经过 Base64 编码 + 固定字节位移
- 伪装成普通资源文件，APK 中资源文件随处可见
- 安全性最低，但增加逆向者定位所有密钥源的难度

```
存储值 = Base64(Derive-C) 的字节 → 每个字节 +0x37 位移
读取时: 字节 -0x37 → Base64 解码 → Derive-C
```

#### 2.3.6 运行时密钥重组

```
StubApplication.attachBaseContext(baseContext)
    │
    ├─ 1. Derive-A = SHA-256(packageName + "|" + minSdk + "|"
    │                        + targetSdk + "|" + certHash)[0:16]
    │
    ├─ 2. Derive-B = KeyProvider.getKeyPart()  // JNI → .so 提取
    │
    ├─ 3. Derive-C = decodeResource(R.raw.trilodata)
    │
    └─ 4. seed_16 = Derive-A ^ Derive-B ^ Derive-C
         │
         └─ MasterKey = HKDF-SHA256(seed_16, salt="triloSec", info=dexName)
              └─ 派生为 32 bytes AES-GCM key
```

> 使用 HKDF 而非直接截取，是因为 XOR 后只有 16 bytes，需要通过 KDF 扩展为 AES-256 所需的 32 bytes。每个 DEX 文件使用不同的 info 参数派生独立密钥。

#### 2.3.7 密钥生成流程 (CLI 加固时)

```
Step 1: 生成 16 字节随机 seed
Step 2: 用 debug keystore 签名 APK → 获取签名证书 hash
Step 3: Derive-A = SHA-256(packageName|minSdk|targetSdk|certHash)[0:16]
Step 4: Derive-B = random(16 bytes)  // 随机生成
Step 5: Derive-C = seed ^ Derive-A ^ Derive-B  // 满足 XOR 关系
Step 6: 用 HKDF(seed) 派生 32B AES key 加密 DEX
Step 7: 编译 libtrilocfg.so (注入 Derive-B 混淆数据)
Step 8: 生成 res/raw/trilodata.bin (写入 Derive-C 编码数据)
```

### 2.4 Stub 运行时设计

#### 2.4.1 注入点

修改 `AndroidManifest.xml` 中 `<application>` 标签的 `android:name` 属性，指向注入的 `com.trilo.stub.StubApplication`。

```xml
<!-- 加固前 -->
<application android:name="com.example.MyApp" ...>

<!-- 加固后 -->
<application android:name="com.trilo.stub.StubApplication" ...>
```

#### 2.4.2 StubApplication 执行流程

```
Application.attachBaseContext(baseContext)
    │
    ├─ 1. 密钥重组 (reconstructMasterKey)
    │     ├─ Key-A = NativeKeyProvider.getKeyA()       // JNI 从 .so 获取
    │     ├─ Key-B = 读取并解码 res/raw/trilodata.bin   // APK 资源
    │     ├─ Key-C = SHA-256(签名证书)[0:16]            // 签名派生
    │     └─ MasterKey = (Key-A || Key-B || Key-C)[0:32]
    │
    ├─ 2. 读取 assets/.dexmeta 元数据
    │     └─ 获取文件列表、nonce、GCM tag
    │
    ├─ 3. 对每个加密文件:
    │     ├─ 从 assets/ 读取 .dat 文件
    │     ├─ 解析文件头: 提取 nonce (前 12B) + GCM tag (接下来 16B)
    │     ├─ AES-256-GCM 解密剩余数据
    │     │     ├─ GCM tag 校验失败 → AEADBadTagException → 重打包攻击检测
    │     │     └─ 解密成功 → 明文 DEX 字节
    │     └─ ByteBuffer.allocateDirect(明文) → ByteBuffer[]
    │
    ├─ 4. new InMemoryDexClassLoader(ByteBuffer[], null)
    │     └─ 直接从内存加载 DEX，不落盘
    │
    ├─ 5. 反射替换 ClassLoader 链:
    │     ├─ 获取 context.getClassLoader() → PathClassLoader
    │     ├─ 反射读取 pathClassLoader.pathList.dexElements (原始)
    │     ├─ 反射读取 memoryLoader.pathList.dexElements (解密后的)
    │     └─ 合并: dexElements = [stubElements, originalElements]
    │
    └─ 6. super.attachBaseContext(baseContext)
          └─ 继续正常 Application 生命周期
             Application.onCreate() → 原始 Application
```

#### 2.4.3 关键技术点

**InMemoryDexClassLoader（API 26+）：**

- Android 8.0 引入，接受 `ByteBuffer[]` 参数
- DEX 数据始终在内存中，不写入文件系统
- ART 直接从 ByteBuffer 解析并加载类

**反射替换 dexElements：**

ART 的类加载通过 `BaseDexClassLoader` → `DexPathList` → `Element[] dexElements` 链完成。通过反射将解密后的 DEX Element 插入到数组头部，使后续类查找优先从解密后的 DEX 中定位。

```
反射路径:
  BaseDexClassLoader
    └─ field: pathList (DexPathList)
         └─ field: dexElements (Element[])
```

### 2.5 APK 打包规则

| 文件类型 | ZIP 压缩模式 | 原因 |
|---|---|---|
| `AndroidManifest.xml` | STORED (不压缩) | Android 系统要求 |
| `classes*.dex` | STORED (不压缩) | ART 内存映射需要 |
| 其他资源文件 | DEFLATED | 减小体积 |
| `META-INF/` | 删除 | 旧签名失效，重新签名会生成 |

---

## 3. CLI 工具设计

### 3.1 命令行接口

```
trilodex <input.apk> [选项]

参数:
  input.apk                  要加固的 APK 文件路径

选项:
  -o, --output PATH          输出文件路径 (默认: <输入名>_protected.apk)
  -k, --key HEX              AES-256 密钥 (64位十六进制，不指定则随机生成)
  --sdk-dir PATH             Android SDK 根目录 (用于 aapt2/zipalign/apksigner)
  --skip-sign                跳过 APK 签名步骤
  --skip-verify              跳过前置工具检查
  -v, --verbose              输出详细日志
  --help                     显示帮助信息
```

### 3.2 使用示例

```bash
# 基本用法 (自动生成密钥, 跳过签名)
trilodex app.apk -o app_protected.apk --skip-sign

# 指定 SDK, 自动签名
trilodex app.apk --sdk-dir /path/to/android-sdk

# 使用自定义密钥
trilodex app.apk -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

# 详细日志
trilodex app.apk -v
```

### 3.3 输出示例

```
[*] TriloDexPack v0.1.0
[*] Loading APK: app.apk
[*] Found 2 DEX files: classes.dex (1.2 MB), classes2.dex (0.8 MB)
[*] Generating AES key...
[*] Encrypting classes.dex...
[*] Encrypting classes2.dex...
[*] Compiling stub...
[*] Modifying manifest...
[*] Repackaging APK...
[*] Running zipalign...
[*] Signing APK...
[+] Protected APK saved to: app_protected.apk
[+] AES Key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
[!] 请妥善保管 AES 密钥!
```

---

## 4. 项目结构

```
triloDexPack/
├── README.md                         # 项目说明
├── pyproject.toml                    # Python 包定义
├── trilo_dex/
│   ├── __init__.py
│   ├── cli.py                        # CLI 入口 (click)
│   ├── protector.py                  # 主流程编排
│   ├── parser.py                     # APK 解压 + DEX 文件发现
│   ├── encryptor.py                  # triloSec (AES-256-GCM) 加密
│   ├── manifest.py                   # AXML 反编译/修改/回编
│   ├── smali_injector.py             # Stub smali 编译与注入
│   ├── native_build.py               # 编译 libtrilocfg.so (注入 Key-A)
│   ├── repacker.py                   # APK 重新打包 (ZIP)
│   ├── signer.py                     # APK 签名 (apksigner)
│   └── tools.py                      # 外部工具检测与下载
├── stub/
│   ├── StubApplication.smali         # Stub 主类 (密钥重组 + 解密 + 加载)
│   └── NativeKeyProvider.smali       # JNI 接口声明 (getKeyA)
├── native/
│   └── trilocfg.c                    # 极简 native 库 (存储 Key-A)
└── tests/
    ├── test_parser.py
    ├── test_encryptor.py
    └── test_protector.py
```

### 4.1 模块职责

| 模块 | 职责 |
|---|---|
| `cli.py` | 解析命令行参数，调用 protector，输出结果 |
| `protector.py` | 主流程编排：解析→生成密钥→加密→编译 native/so→编译 stub→注入→改 manifest→打包→签名 |
| `parser.py` | ZIP 解压 APK，扫描 classes*.dex，验证 APK 结构 |
| `encryptor.py` | triloSec (AES-256-GCM) 加密 DEX，生成 .dat 文件和 .dexmeta 元数据 |
| `manifest.py` | androguard 反编译 AXML → ElementTree 修改 → aapt2 回编 |
| `smali_injector.py` | smali → 调用 smali.jar 编译 dex |
| `native_build.py` | 生成 8 层混淆的 C 代码 → NDK clang 编译 libtrilocfg.so |
| `repacker.py` | ZIP 重新打包，正确处理 STORED/DEFLATED 模式 |
| `signer.py` | 生成 debug keystore，调用 apksigner 签名，派生 Key-C |
| `tools.py` | 检测 Java、smali.jar、aapt2、zipalign、apksigner、NDK 可用性 |

---

## 5. 技术依赖

### 5.1 Python 依赖

| 库 | 用途 |
|---|---|
| `click` | CLI 参数解析 |
| `cryptography` | AES-256-GCM 加密 (triloSec Layer 1) |
| `androguard` | AXML (二进制 XML) 反编译 |

### 5.2 外部工具

| 工具 | 用途 | 获取方式 |
|---|---|---|
| `java` | 运行 smali.jar | 系统 PATH |
| `smali.jar` | smali → dex 编译 | 自动从 GitHub 下载 |
| `aapt2` | AXML 回编为二进制 | Android SDK build-tools |
| `zipalign` | APK 字节对齐 | Android SDK build-tools |
| `apksigner` | APK 签名 | Android SDK build-tools |
| `clang` / `ndk-build` | 编译 libtrilocfg.so | Android NDK |

### 5.3 Smali 自动下载

```
下载地址: https://github.com/baksmali/smali/releases/download/smali-3.0.7/smali-3.0.7.jar
缓存位置: ~/.trilodex/smali-3.0.7.jar
优先级: SMALI_JAR 环境变量 > 本地缓存 > 自动下载
```

---

## 6. StubApplication Smali 结构

### 6.1 类定义

```
包名: com.trilo.stub
类名: StubApplication
继承: android.app.Application
```

### 6.2 核心字段

```smali
.class public Lcom/trilo/stub/StubApplication;
.super Landroid/app/Application;

; S-Box 逆置换表 (编译时注入)
.field private static SBOX_INV:[B

; 解密后的 DEX 缓冲区
.field private static decryptedDexBuffers:[Ljava/nio/ByteBuffer;
```

> **注意:** Master Key 不存储在 smali 中，而是通过 Key-A (.so) + Key-B (资源) + Key-C (签名) 三片重组。

### 6.3 NativeKeyProvider (JNI 类)

```smali
.class public Lcom/trilo/stub/NativeKeyProvider;
.super Ljava/lang/Object;

; native 方法，从 libtrilocfg.so 获取 Key-A
.method public native getKeyA()[B
```

### 6.4 核心方法

**reconstructMasterKey(Context) → byte[]**
- 调用 NativeKeyProvider.getKeyA() 获取 Key-A (16 bytes)
- 从 res/raw/trilodata.bin 读取并 XOR 解码得到 Key-B (16 bytes)
- 通过 PackageManager 获取 APK 签名证书 → SHA-256 → 取前 16 bytes 作为 Key-C
- 拼接 Key-A || Key-B || Key-C → 取前 32 bytes 作为 AES-256-GCM key

**inverseSBox(byte[]) → byte[]** (V2 扩展)
- 预留接口，V2 可加入 S-Box 置换层

**aesGcmDecrypt(byte[], key, nonce, tag) → byte[]**
- Cipher.getInstance("AES/GCM/NoPadding")
- GCMParameterSpec(128, nonce)
- cipher.init(DECRYPT_MODE, keySpec, gcmSpec)
- cipher.doFinal(ciphertext) → 明文 DEX
- GCM tag 校验失败 → AEADBadTagException → 说明密文被篡改
- triloSec 核心解密

**loadDexFromAssets(Context) → ClassLoader**
- 读取 .dexmeta 获取文件列表
- 对每个 .dat: 解析文件头 → aesGcmDecrypt → 明文 DEX
- ByteBuffer.allocateDirect(明文) 收集到数组
- new InMemoryDexClassLoader(ByteBuffer[], null)

**installDexElements(ClassLoader, ClassLoader)**
- 反射读取两个 loader 的 pathList.dexElements
- 合并数组：stub 的元素在前，原始元素在后
- 反射写回原始 loader 的 dexElements

**attachBaseContext(Context)**
- 调用 reconstructMasterKey 重组密钥
- 调用 loadDexFromAssets 获取 memoryLoader
- 调用 installDexElements 替换 dexElements
- 调用 super.attachBaseContext

---

## 7. 完整加固流程

```
Step 1: 前置检查
  ├─ 验证输入 APK 存在
  ├─ 检测 java 可用
  ├─ 检测/下载 smali.jar
  └─ 检测 aapt2/zipalign/apksigner (--sdk-dir)

Step 2: 解压 APK
  └─ ZIP 解压到临时目录，验证 AndroidManifest.xml + 至少 1 个 DEX

Step 3: 发现 DEX
  └─ 扫描 classes.dex, classes2.dex, classes3.dex, ...

Step 4: 加密 DEX
  ├─ 生成 48 字节随机 Master Key
  ├─ 拆分: Key-A(16B) + Key-B(16B) + Key-C(16B)
  ├─ 用 debug keystore 签名临时 APK → 派生 Key-C → 验证匹配
  ├─ 每个 DEX → triloSec (AES-256-GCM) 加密 → assets/encrypted_classesN.dat
  ├─ 生成 assets/.dexmeta 元数据
  └─ 删除原始 DEX 文件

Step 5: 编译密钥载体
  ├─ 编译 libtrilocfg.so (C代码注入 Key-A XOR 数据) → lib/arm64-v8a/
  └─ 生成 res/raw/trilodata.bin (Key-B XOR 编码数据)

Step 6: 编译 Stub
  ├─ 复制 StubApplication.smali + NativeKeyProvider.smali 到临时目录
  └─ java -jar smali.jar -o stub.dex

Step 6: 注入 Stub
  ├─ stub.dex → classes.dex (替换)
  └─ 删除所有原始 classes*.dex

Step 7: 修改 Manifest
  ├─ androguard AXMLPrinter 反编译 AXML → 文本 XML
  ├─ ElementTree 修改 android:name = "com.trilo.stub.StubApplication"
  └─ aapt2 compile 回编为二进制 AXML

Step 8: 清理签名
  └─ 删除 META-INF/

Step 9: 打包
  └─ ZIP: manifest/dex = STORED, 其余 = DEFLATED

Step 10: zipalign (如果提供了 SDK)
  └─ zipalign -f -p 4

Step 11: 签名 (除非 --skip-sign)
  ├─ 生成 debug keystore (如无)
  └─ apksigner sign (v1 + v2)

Step 12: 清理临时目录，输出结果
```

---

## 8. 异常处理

### 8.1 异常层次

```
TriloDexError (基础异常)
├── ApkError               APK 文件无效/损坏
│   └── DexNotFoundError   未找到 DEX 文件
├── ManifestError           Manifest 解析/修改失败
├── EncryptionError         加密失败
├── SmaliError              smali 编译失败
├── ToolNotFoundError       必需工具缺失
└── SigningError            签名失败
```

### 8.2 错误场景处理

| 场景 | 异常类型 | 处理方式 |
|---|---|---|
| 输入文件不存在 | ApkError | 提示路径错误，退出 |
| 非 ZIP 文件 | ApkError | 提示格式无效，退出 |
| 无 DEX 文件 | DexNotFoundError | 提示 APK 不含 DEX，退出 |
| 无 AndroidManifest.xml | ManifestError | 提示 Manifest 缺失，退出 |
| smali.jar 下载失败 | ToolNotFoundError | 提示手动指定路径，退出 |
| Java 未安装 | ToolNotFoundError | 提示安装 Java，退出 |
| smali 编译失败 | SmaliError | 输出 smali 错误信息，退出 |
| aapt2 未找到 | ToolNotFoundError | 提示提供 --sdk-dir，退出 |
| apksigner 失败 | SigningError | 输出签名错误，退出 |

---

## 9. 安全分析

### 9.1 V1 防护能力

| 攻击面 | 防护效果 | 说明 |
|---|---|---|
| 静态反编译 (jadx, apktool) | **有效** | DEX 以 GCM 密文存储，无法直接反编译 |
| DEX 拖壳 (内存 dump) | **部分防护** | 内存中可 dump，需要动态分析能力 |
| 密钥提取 | **较强** | 密钥三分片: .so + 资源 + 签名派生，需同时定位三处 |
| 密文篡改 | **有效** | GCM auth tag 校验，篡改必然失败 |
| 重打包攻击 | **有效** | 重签名后 Key-C 变化 → 密钥错误 → 解密失败 |

### 9.2 V2 增强方向

| 方向 | 描述 |
|---|---|
| 密钥拆分 | AES 密钥分片存储在 smali + .so native 中 |
| 设备绑定 | 用设备指纹 (IMEI/AndroidID/序列号) 派生密钥 |
| 反调试 | 检测 debugger、模拟器、root 环境 |
| 完整性校验 | 运行时校验 DEX 和 .so 的 hash |
| .so 加密 | native 库也进行加密保护 |
| 字符串加密 | stub 中的关键字符串加密存储 |
| 控制流混淆 | stub 代码加入花指令、不透明谓词 |
| 远程密钥 | 运行时从服务器获取解密密钥 |

---

## 10. V1 与 V2 范围

### V1 包含
- [x] triloSec (AES-256-GCM) 加密所有 DEX
- [x] 密钥三分片: .so (Key-A) + 资源 (Key-B) + 签名 (Key-C)
- [x] InMemoryDexClassLoader 内存加载 (API 26+)
- [x] StubApplication + NativeKeyProvider smali
- [x] 编译极简 libtrilocfg.so (注入 Key-A)
- [x] aapt2 修改 Manifest
- [x] zipalign + apksigner 完整打包
- [x] debug keystore 自动生成
- [x] smali.jar 自动下载
- [x] 基础错误处理

### V2 规划
- [ ] 自定义 keystore 签名 (CLI 参数)
- [ ] 批量 APK 处理
- [ ] 反调试/反篡改/模拟器检测
- [ ] .so native 库加密
- [ ] 资源文件 (resources.arsc) 保护
- [ ] 纯 Python AXML 解析 (去 aapt2 依赖)
- [ ] 配置文件支持 (.trilodex.yaml)
- [ ] SaaS Web 平台

---

## 11. 风险与限制

| 风险 | 影响 | 应对 |
|---|---|---|
| 多 DEX 应用可能加载失败 | 加固后无法运行 | 充分测试 multi-dex APK，确保 dexElements 合并正确 |
| aapt2 版本兼容性 | Manifest 回编失败 | 测试多个 build-tools 版本 (33.0.x, 34.0.x) |
| 大 APK 处理慢 | 用户体验差 | V2 加入进度条，优化加密流程 |
| StubApplication 与原 Application 冲突 | 生命周期异常 | V2 支持 Application 代理模式 |
| 不同厂商 ROM 的 ART 差异 | 部分设备崩溃 | 广泛测试主流厂商设备 |
