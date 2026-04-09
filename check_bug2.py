import struct
import zipfile

def extract_manifest(apk_path):
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read('AndroidManifest.xml')

orig = extract_manifest('samples/com-gotenna-proag_1.6.0.apk')
mod = extract_manifest('output/protected.apk')

# The string data is inserted at last_end (= 10372 in original coords)
# After offset table insertion at 668, last_end shifts to 10376
# So string data is inserted at 10376

# But RESOURCE_MAP starts at 10372 (original), shifts to 10376 after offset insertion
# So string data is inserted AT the same position where RESOURCE_MAP now starts!

# Let's verify by checking the bytes between the end of the new string data
# and the start of RESOURCE_MAP

# In modified:
# String pool starts at 8
# String pool size = 10434
# So pool data = bytes 8 to 10441
# RESOURCE_MAP starts at 10442

# New string is at file offset 10378, length 64 bytes (including header)
# So new string occupies bytes 10378 to 10441
# That's 64 bytes: 2 (length) + 60 (text) + 2 (null) = 64

# After the new string (at 10442) should be RESOURCE_MAP
# But wait, what's between the end of the last ORIGINAL string and the start of RESOURCE_MAP?

# In original:
# Last string (index 157) is "theme" at offset 646 relative
# Absolute: 688 + 646 = 1334
# "theme" in UTF-16: 05 00 74 00 68 00 65 00 6d 00 65 00 00 00 = 14 bytes
# Ends at: 1334 + 14 = 1348

# But pool ends at 10372! So there's a LOT of data after "theme"
# That means "theme" is NOT the last string by position

# Let me find the actual last string by position
pool = 8
orig_ss = struct.unpack_from('<I', orig, pool+20)[0]
orig_sc = struct.unpack_from('<I', orig, pool+8)[0]
string_data = pool + orig_ss

max_pos = 0
max_idx = -1
for i in range(orig_sc):
    off = struct.unpack_from('<I', orig, pool + 28 + i*4)[0]
    abs_pos = string_data + off
    # Read length
    length = struct.unpack_from('<H', orig, abs_pos)[0]
    abs_pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', orig, abs_pos)[0]
        abs_pos += 2
    end_pos = abs_pos + length * 2 + 2  # +2 for null terminator
    if end_pos > max_pos:
        max_pos = end_pos
        max_idx = i

s = orig[string_data + struct.unpack_from('<I', orig, pool + 28 + max_idx*4)[0]:]
length = struct.unpack_from('<H', s, 0)[0]
sp = 2
if length & 0x8000:
    length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', s, sp)[0]
    sp += 2
text = s[sp:sp + length * 2].decode('utf-16-le', errors='replace')

print(f"Original last string by position: [{max_idx}] = '{text[:40]}'")
print(f"  Ends at: {max_pos}")
print(f"  Pool ends at: {pool + struct.unpack_from('<I', orig, pool+4)[0]}")
print(f"  Bytes after last string: {pool + struct.unpack_from('<I', orig, pool+4)[0] - max_pos}")

# What are those trailing bytes?
trailing = orig[max_pos:pool + struct.unpack_from('<I', orig, pool+4)[0]]
if trailing:
    print(f"  Trailing bytes: {trailing.hex(' ')}")
else:
    print(f"  No trailing bytes (last string ends at pool boundary)")

# Now check: in the modified file, what's at the end of the string pool?
mod_ss = struct.unpack_from('<I', mod, pool+20)[0]
mod_sc = struct.unpack_from('<I', mod, pool+8)[0]
mod_string_data = pool + mod_ss

max_pos = 0
max_idx = -1
for i in range(mod_sc):
    off = struct.unpack_from('<I', mod, pool + 28 + i*4)[0]
    abs_pos = mod_string_data + off
    length = struct.unpack_from('<H', mod, abs_pos)[0]
    abs_pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', mod, abs_pos)[0]
        abs_pos += 2
    end_pos = abs_pos + length * 2 + 2
    if end_pos > max_pos:
        max_pos = end_pos
        max_idx = i

s = mod[mod_string_data + struct.unpack_from('<I', mod, pool + 28 + max_idx*4)[0]:]
length = struct.unpack_from('<H', s, 0)[0]
sp = 2
if length & 0x8000:
    length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', s, sp)[0]
    sp += 2
text = s[sp:sp + length * 2].decode('utf-16-le', errors='replace')

print(f"\nModified last string by position: [{max_idx}] = '{text[:40]}'")
print(f"  Ends at: {max_pos}")
print(f"  Pool ends at: {pool + struct.unpack_from('<I', mod, pool+4)[0]}")
print(f"  Bytes after last string: {pool + struct.unpack_from('<I', mod, pool+4)[0] - max_pos}")

trailing = mod[max_pos:pool + struct.unpack_from('<I', mod, pool+4)[0]]
if trailing:
    print(f"  Trailing bytes: {trailing.hex(' ')}")
else:
    print(f"  No trailing bytes (last string ends at pool boundary)")

# Now the key question: where was the new string inserted relative to existing strings?
# If it was inserted at position 10376 (which is where RESOURCE_MAP starts after offset insertion)
# But there might be existing strings after position 10372 in the original...

# Actually, the last string in the original ends at some position. Let's see what's between
# that position and the RESOURCE_MAP start.

# Check if any original strings end after position 10372 (pool_size boundary)
print(f"\n=== Checking for strings past pool boundary ===")
for i in range(orig_sc):
    off = struct.unpack_from('<I', orig, pool + 28 + i*4)[0]
    abs_pos = string_data + off
    length = struct.unpack_from('<H', orig, abs_pos)[0]
    abs_pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', orig, abs_pos)[0]
        abs_pos += 2
    end_pos = abs_pos + length * 2 + 2
    if end_pos > pool + struct.unpack_from('<I', orig, pool+4)[0]:
        s_text = orig[string_data + off:]
        length2 = struct.unpack_from('<H', s_text, 0)[0]
        sp2 = 2
        if length2 & 0x8000:
            length2 = ((length2 & 0x7FFF) << 16) | struct.unpack_from('<H', s_text, sp2)[0]
            sp2 += 2
        text2 = s_text[sp2:sp2 + length2 * 2].decode('utf-16-le', errors='replace')
        print(f"  String [{i}] '{text2[:30]}' ends at {end_pos}, {end_pos - (pool + struct.unpack_from('<I', orig, pool+4)[0])} bytes past pool end!")

# Also: check the 8 bytes between pool_size and actual data end
orig_pool_end = pool + struct.unpack_from('<I', orig, pool+4)[0]
print(f"\n=== Original: {orig_pool_end} to {max_pos} ===")
print(f"  8 bytes: {orig[orig_pool_end:max_pos+8].hex(' ') if max_pos > orig_pool_end else 'N/A'}")

# What's at position 10364-10372 in original (between pool_size end and pool data end)?
between = orig[orig_pool_end:orig_pool_end+8]
print(f"  Bytes at {orig_pool_end}-{orig_pool_end+8}: {between.hex(' ')}")
