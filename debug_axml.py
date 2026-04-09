import struct
import zipfile

with zipfile.ZipFile('samples/com-gotenna-proag_1.6.0.apk') as zf:
    data = zf.read('AndroidManifest.xml')

base = 8  # string pool starts here
string_count = struct.unpack_from('<I', data, base + 8)[0]
strings_start = struct.unpack_from('<I', data, base + 20)[0]
offset_table = base + 28
string_data = base + strings_start

print(f"string_count={string_count}")
print(f"strings_start={strings_start}")
print(f"offset_table at={offset_table}")
print(f"string_data at={string_data}")

# Check offsets
for i in range(min(20, string_count)):
    off = struct.unpack_from('<I', data, offset_table + i*4)[0]
    abs_pos = string_data + off
    # Read UTF-16 length
    length = struct.unpack_from('<H', data, abs_pos)[0]
    abs_pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, abs_pos)[0]
        abs_pos += 2
    s = data[abs_pos:abs_pos + length * 2].decode('utf-16-le', errors='replace')
    print(f"  [{i:3d}] rel_off={off:5d} abs={string_data+off:5d} len={length:3d} {repr(s[:50])}")

# Also check string 87 ("application") and 124 (GoTennaApplication)
for idx in [87, 124]:
    off = struct.unpack_from('<I', data, offset_table + idx*4)[0]
    abs_pos = string_data + off
    length = struct.unpack_from('<H', data, abs_pos)[0]
    abs_pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, abs_pos)[0]
        abs_pos += 2
    s = data[abs_pos:abs_pos + length * 2].decode('utf-16-le', errors='replace')
    print(f"\n  [{idx}] rel_off={off} abs={string_data+off} len={length} {repr(s)}")
