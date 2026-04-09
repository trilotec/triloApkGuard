import struct
import zipfile

def extract_manifest(apk_path):
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read('AndroidManifest.xml')

orig = extract_manifest('samples/com-gotenna-proag_1.6.0.apk')
mod = extract_manifest('output/protected.apk')

# Original pool
pool = 8
orig_pool_size = struct.unpack_from('<I', orig, pool+4)[0]
orig_sc = struct.unpack_from('<I', orig, pool+8)[0]
orig_ss = struct.unpack_from('<I', orig, pool+20)[0]
orig_string_data = pool + orig_ss
orig_last_rel = struct.unpack_from('<I', orig, pool + 28 + (orig_sc-1)*4)[0]
orig_last_abs = orig_string_data + orig_last_rel
orig_len = struct.unpack_from('<H', orig, orig_last_abs)[0]
orig_last_abs += 2
if orig_len & 0x8000:
    orig_len = ((orig_len & 0x7FFF) << 16) | struct.unpack_from('<H', orig, orig_last_abs)[0]
    orig_last_abs += 2
orig_last_end = orig_last_abs + orig_len * 2 + 2  # +2 null terminator

print("=== ORIGINAL last string ===")
print(f"  pool_size: {orig_pool_size}")
print(f"  pool end: {pool + orig_pool_size}")
print(f"  last string ends at: {orig_last_end}")
print(f"  expected padding: {(4 - (orig_last_end % 4)) % 4}")

# Modified pool
mod_pool_size = struct.unpack_from('<I', mod, pool+4)[0]
mod_sc = struct.unpack_from('<I', mod, pool+8)[0]
mod_ss = struct.unpack_from('<I', mod, pool+20)[0]
mod_string_data = pool + mod_ss
mod_last_rel = struct.unpack_from('<I', mod, pool + 28 + (mod_sc-1)*4)[0]
mod_last_abs = mod_string_data + mod_last_rel
mod_len = struct.unpack_from('<H', mod, mod_last_abs)[0]
mod_last_abs += 2
if mod_len & 0x8000:
    mod_len = ((mod_len & 0x7FFF) << 16) | struct.unpack_from('<H', mod, mod_last_abs)[0]
    mod_last_abs += 2
mod_last_end = mod_last_abs + mod_len * 2 + 2

print(f"\n=== MODIFIED last string ===")
print(f"  pool_size header: {mod_pool_size}")
print(f"  pool end (pool + pool_size): {pool + mod_pool_size}")
print(f"  last string ends at: {mod_last_end}")

# Calculate what pool_size SHOULD be
expected_pool_size = orig_pool_size + (mod_last_end - orig_last_end) + 4  # +4 for offset entry
print(f"\n=== pool_size analysis ===")
print(f"  Original pool_size: {orig_pool_size}")
print(f"  Last string end delta: {mod_last_end - orig_last_end}")
print(f"  +4 for offset table entry")
print(f"  Expected pool_size: {expected_pool_size}")
print(f"  Actual pool_size:   {mod_pool_size}")
print(f"  Difference: {mod_pool_size - expected_pool_size}")

# Also verify: does the RESOURCE_MAP chunk start at the right position?
print(f"\n=== Chunk positions ===")
print(f"  ORIG: STRING_POOL ends at {pool + orig_pool_size}, RESOURCE_MAP starts at {pool + orig_pool_size}")
print(f"  MOD:  STRING_POOL ends at {pool + mod_pool_size}, RESOURCE_MAP starts at {pool + mod_pool_size}")

# Check RESOURCE_MAP at expected position
rm_pos = pool + mod_pool_size
rm_type = struct.unpack_from('<H', mod, rm_pos)[0]
rm_size = struct.unpack_from('<I', mod, rm_pos+4)[0]
print(f"  At file offset {rm_pos}: type=0x{rm_type:04x} size={rm_size}")
if rm_type == 0x0180:
    print(f"  RESOURCE_MAP found at correct position")
    n_resources = rm_size // 4
    print(f"  Number of resource entries: {n_resources}")
else:
    print(f"  ERROR: Expected RESOURCE_MAP (0x0180), got 0x{rm_type:04x}")

# Check if pool_size causes reading into next chunk
print(f"\n=== Overlap check ===")
print(f"  Pool claims to end at: {pool + mod_pool_size}")
print(f"  Actual last string ends at: {mod_last_end}")
if pool + mod_pool_size > mod_last_end:
    print(f"  Pool extends {pool + mod_pool_size - mod_last_end} bytes PAST last string data")
    print(f"  This means parser will read {pool + mod_pool_size - mod_last_end} bytes of garbage/padding")
    garbage = mod[mod_last_end:pool + mod_pool_size]
    print(f"  Garbage bytes: {garbage.hex(' ')}")
elif pool + mod_pool_size < mod_last_end:
    print(f"  Pool is SHORT by {mod_last_end - (pool + mod_pool_size)} bytes")
    print(f"  This means last string is OUTSIDE the declared pool - CORRUPTION!")
else:
    print(f"  Pool ends exactly at last string end - OK")
