import struct

with open('output/test_modified_manifest.xml', 'rb') as f:
    data = f.read()

pool = 8
pool_size = struct.unpack_from('<I', data, pool+4)[0]
string_count = struct.unpack_from('<I', data, pool+8)[0]
strings_start = struct.unpack_from('<I', data, pool+20)[0]

# String data area
string_data_abs = pool + strings_start
offset_table_end = pool + 28 + string_count * 4

# Total string data size
string_data_size = (pool + pool_size) - string_data_abs

print(f"Pool size: {pool_size}")
print(f"String data starts at: {string_data_abs}")
print(f"Offset table ends at: {offset_table_end}")
print(f"Pool data ends at: {pool + pool_size}")
print(f"String data size: {string_data_size}")
print(f"String data size mod 4: {string_data_size % 4}")

# The warning says "Size of strings is not aligned by four bytes"
# This means string_data_size % 4 != 0

# Let's also check what androguard considers the "size of strings"
# It's likely: pool_size - strings_start
androguard_strings_size = pool_size - strings_start
print(f"\nAndroguard 'size of strings': {androguard_strings_size}")
print(f"Mod 4: {androguard_strings_size % 4}")

# What SHOULD it be for 4-byte alignment?
target_size = ((androguard_strings_size + 3) // 4) * 4
padding_needed = target_size - androguard_strings_size
print(f"Need {padding_needed} bytes of padding for 4-byte alignment")

# Check the original
with open('samples/com-gotenna-proag_1.6.0.apk', 'rb') as zf:
    import zipfile
    with zipfile.ZipFile(zf) as z:
        orig_data = z.read('AndroidManifest.xml')

orig_pool_size = struct.unpack_from('<I', orig_data, pool+4)[0]
orig_strings_start = struct.unpack_from('<I', orig_data, pool+20)[0]
orig_strings_size = orig_pool_size - orig_strings_start
print(f"\nOriginal 'size of strings': {orig_strings_size}")
print(f"Original mod 4: {orig_strings_size % 4}")

# So both original and modified have unaligned string data sizes
# The difference: original had X bytes unaligned, modified has Y bytes unaligned

# The real issue might be that when we insert data, we break the existing alignment
# Let's see what the actual alignment situation is

# Original:
# strings_start = some value
# string_data_size = pool_size - strings_start
# If this is not divisible by 4, it's "not aligned"

# But the original APK works on Android, so this isn't necessarily fatal

# Let me check: what if we add 4-byte padding at the end to align?
current_end = pool + pool_size
print(f"\nCurrent pool data ends at: {current_end}")
print(f"Next chunk (RESOURCE_MAP) starts at: {current_end}")

# If we add (4 - (string_data_size % 4)) % 4 bytes of null padding
# before RESOURCE_MAP, the string data would be aligned

# But actually, the real question is: does Android REJECT the unaligned manifest?
# Let's check by looking at the actual error more carefully

# The warning from androguard is:
# "Size of strings is not aligned by four bytes."
# This is at line 174 of androguard/core/axml.py

# Androguard still parses it successfully (is_valid = True)
# So this is a warning, not a fatal error

# But Android's native XML parser might be stricter

# The fix would be to add 4-byte padding at the end of the string pool
# Let's calculate how much padding is needed

alignment = string_data_size % 4
if alignment != 0:
    padding_needed = 4 - alignment
    print(f"\nString data needs {padding_needed} bytes of padding for 4-byte alignment")
    print(f"Current pool_size: {pool_size}")
    print(f"Corrected pool_size: {pool_size + padding_needed}")
    print(f"Corrected container size: {struct.unpack_from('<I', data, 4)[0] + padding_needed}")

# Let's also check: in the ORIGINAL file, what was the situation?
# If the original also had unaligned strings, then this isn't the issue
