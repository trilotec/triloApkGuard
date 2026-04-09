import struct
import zipfile

def extract_manifest(apk_path):
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read('AndroidManifest.xml')

orig = extract_manifest('samples/com-gotenna-proag_1.6.0.apk')
mod = extract_manifest('output/protected.apk')

# Key insight: the string data insert_pos is at last_end (10372 in original coords)
# After offset table insertion at 668, last_end shifts to 10376
# But RESOURCE_MAP was originally at 10372, shifts to 10376 after offset insertion
# So string data is inserted AT the start of RESOURCE_MAP!

# Let's verify
pool = 8
orig_pool_size = struct.unpack_from('<I', orig, pool+4)[0]
print(f"Original pool_size: {orig_pool_size}")
print(f"Original pool ends at: {pool + orig_pool_size}")

# Where is RESOURCE_MAP in original?
rm_pos_orig = pool + orig_pool_size
print(f"RESOURCE_MAP starts at: {rm_pos_orig}")

# Now in modified:
# After offset table insertion at 668, everything after 668 shifts by 4
# RESOURCE_MAP moves from 10372 to 10376
# Then string data insertion at 10376 (after offset insertion)
# RESOURCE_MAP moves from 10376 to 10376 + (64 + 0 padding) = 10440

# But actual RESOURCE_MAP is at 10442!
mod_pool_size = struct.unpack_from('<I', mod, pool+4)[0]
actual_rm_pos = pool + mod_pool_size
print(f"\nActual modified pool ends at: {pool + mod_pool_size}")
print(f"Expected RM position after insertions: 10440")
print(f"Difference: {actual_rm_pos - 10440}")

# Let me check what's at 10440
print(f"\nBytes at 10440-10445 in modified:")
for i in range(6):
    b = mod[10440 + i]
    print(f"  [{10440+i}] 0x{b:02x}")

# The RESOURCE_MAP type should be 0x0180
rm_type = struct.unpack_from('<H', mod, actual_rm_pos)[0]
print(f"\nType at actual RM pos ({actual_rm_pos}): 0x{rm_type:04x}")

# What about 2 bytes before?
rm_type_before = struct.unpack_from('<H', mod, actual_rm_pos - 2)[0]
print(f"Type at {actual_rm_pos - 2}: 0x{rm_type_before:04x}")

# Check the null terminator position of the new string
# String at index 158, rel offset 9706
mod_ss = struct.unpack_from('<I', mod, pool+20)[0]
string_data = pool + mod_ss
new_str_abs = string_data + 9706
print(f"\nNew string absolute position: {new_str_abs}")

# Read the string
length = struct.unpack_from('<H', mod, new_str_abs)[0]
new_str_abs += 2
s = mod[new_str_abs:new_str_abs + length * 2].decode('utf-16-le')
null_after = new_str_abs + length * 2
print(f"String: '{s}'")
print(f"Null terminator at: {null_after}-{null_after+1}")
print(f"Pool data ends at (pool + pool_size): {pool + mod_pool_size}")
print(f"Null terminator vs pool end: {null_after + 2 - (pool + mod_pool_size)} bytes past")

# THE BUG: pool_size is calculated as original + new_entry + padding + 4
# But original pool_size was already slightly off (didn't include null terminator)
# So the new pool_size is also off, causing the null terminator to be OUTSIDE the pool!

# Calculate what pool_size SHOULD be:
# It should be: position_of_last_null_terminator + 2 - pool
correct_pool_size = null_after + 2 - pool
print(f"\nCorrect pool_size should be: {correct_pool_size}")
print(f"Actual pool_size: {mod_pool_size}")
print(f"Difference: {correct_pool_size - mod_pool_size}")

if correct_pool_size > mod_pool_size:
    print(f"\n  BUG CONFIRMED: pool_size is {correct_pool_size - mod_pool_size} bytes too short!")
    print(f"  The null terminator of the last string extends {correct_pool_size - mod_pool_size} bytes past the declared pool boundary.")
    print(f"  Android's AXML parser likely reads exactly pool_size bytes, missing the null terminator,")
    print(f"  which could cause string parsing to fail or read garbage.")
