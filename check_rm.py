import struct
import zipfile

def extract_manifest(apk_path):
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read('AndroidManifest.xml')

orig = extract_manifest('samples/com-gotenna-proag_1.6.0.apk')
mod = extract_manifest('output/protected.apk')

# RESOURCE_MAP
# ORIG: starts at 10372, size=164, 39 entries (156 bytes) + 8 byte header = 164
# MOD: starts at 10442 (10372+70), size=164+8=172?, 41 entries?

for label, data in [("ORIG", orig), ("MOD", mod)]:
    # Find RESOURCE_MAP
    pos = 8
    pool_type = struct.unpack_from('<H', data, pos)[0]
    pool_size = struct.unpack_from('<I', data, pos+4)[0]
    pos += pool_size  # Move to next chunk

    rm_type = struct.unpack_from('<H', data, pos)[0]
    rm_header = struct.unpack_from('<H', data, pos+2)[0]
    rm_size = struct.unpack_from('<I', data, pos+4)[0]

    print(f"\n=== {label} RESOURCE_MAP ===")
    print(f"  Position: {pos}")
    print(f"  Type: 0x{rm_type:04x}")
    print(f"  Header: {rm_header}")
    print(f"  Size: {rm_size}")
    n_entries = (rm_size - 8) // 4 if rm_size > 8 else 0
    print(f"  Entries: {n_entries}")

    if rm_type == 0x0180:
        # Print all resource IDs
        for i in range(min(n_entries, 50)):
            rid = struct.unpack_from('<I', data, pos + 8 + i*4)[0]
            print(f"    [{i:2d}] 0x{rid:08x}")
        if n_entries > 50:
            print(f"    ... and {n_entries - 50} more")

# Now let's compare byte-by-byte around the insertion point
# The offset table insertion at 668 shifts everything after by 4 bytes
# Then the string data insertion at ~10378 shifts everything after by ~70 bytes
# RESOURCE_MAP is at 10372 in original, should be at 10372+4=10376 after offset insertion
# Then the string data insertion is at last_end+pad = 10372+0=10372 in original coords
# But after offset insertion, that's at 10376. And we insert at 10376+4=10380?

# Actually let me trace through the actual insertions
print("\n=== Insertion trace ===")
pool = 8
orig_sc = struct.unpack_from('<I', orig, pool+8)[0]
orig_ss = struct.unpack_from('<I', orig, pool+20)[0]
string_data_start = pool + orig_ss

# Last string end
last_rel = struct.unpack_from('<I', orig, pool + 28 + (orig_sc-1)*4)[0]
last_abs = string_data_start + last_rel
last_len = struct.unpack_from('<H', orig, last_abs)[0]
last_abs += 2
if last_len & 0x8000:
    last_len = ((last_len & 0x7FFF) << 16) | struct.unpack_from('<H', orig, last_abs)[0]
    last_abs += 2
last_end = last_abs + last_len * 2 + 2

print(f"  offset_table_end: {pool + 28 + orig_sc * 4}")  # = 668
print(f"  last string end: {last_end}")  # = 10372
print(f"  pad: {(4 - (last_end % 4)) % 4}")
print(f"  string data insert_pos (after offset insertion): {last_end + (4 - (last_end % 4)) % 4 + 4}")
print(f"  RESOURCE_MAP original pos: {pool + struct.unpack_from('<I', orig, pool+4)[0]}")
print(f"  RESOURCE_MAP after offset insert: {pool + struct.unpack_from('<I', orig, pool+4)[0] + 4}")
print(f"  RESOURCE_MAP after string insert: {pool + struct.unpack_from('<I', orig, pool+4)[0] + 4 + (64 + (4 - (last_end % 4)) % 4)}")

# Compare RESOURCE_MAP data between original and modified
# ORIG at 10372, MOD at 10442
print("\n=== RESOURCE_MAP data comparison ===")
orig_rm_data = orig[10372+8:10372+164]
mod_rm_data = mod[10442+8:10442+172]
print(f"  ORIG RM data ({len(orig_rm_data)} bytes):")
for i in range(0, min(len(orig_rm_data), 164), 4):
    rid = struct.unpack_from('<I', orig_rm_data, i)[0]
    print(f"    [{i//4:2d}] 0x{rid:08x}")

print(f"  MOD RM data ({len(mod_rm_data)} bytes):")
for i in range(0, min(len(mod_rm_data), 172), 4):
    rid = struct.unpack_from('<I', mod_rm_data, i)[0]
    print(f"    [{i//4:2d}] 0x{rid:08x}")
