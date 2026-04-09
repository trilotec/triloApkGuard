import struct
import zipfile

def extract_manifest(apk_path):
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read('AndroidManifest.xml')

def check_pool_integrity(data, label):
    pool = 8  # after container
    type_ = struct.unpack_from('<H', data, pool)[0]
    header_sz = struct.unpack_from('<H', data, pool+2)[0]
    pool_size = struct.unpack_from('<I', data, pool+4)[0]
    string_count = struct.unpack_from('<I', data, pool+8)[0]
    style_count = struct.unpack_from('<I', data, pool+12)[0]
    flags = struct.unpack_from('<I', data, pool+16)[0]
    strings_start = struct.unpack_from('<I', data, pool+20)[0]
    styles_start = struct.unpack_from('<I', data, pool+24)[0]

    print(f"\n=== {label} ===")
    print(f"  pool at file offset: {pool}")
    print(f"  pool_size: {pool_size}")
    print(f"  string_count: {string_count}")
    print(f"  style_count: {style_count}")
    print(f"  flags: 0x{flags:08x} (UTF-8 bit: {bool(flags & 0x100)})")
    print(f"  strings_start (from header): {strings_start}")
    print(f"  styles_start (from header): {styles_start}")

    # Expected layout
    offset_table_start = pool + 28
    offset_table_size = string_count * 4
    offset_table_end = offset_table_start + offset_table_size
    string_data_start = pool + strings_start

    print(f"  offset_table: file {offset_table_start} - {offset_table_end}")
    print(f"  string_data starts at: {string_data_start}")
    print(f"  gap between offset_table_end and string_data: {string_data_start - offset_table_end}")

    # Verify: last string should fit within pool
    if string_count > 0:
        last_off = struct.unpack_from('<I', data, offset_table_start + (string_count-1)*4)[0]
        last_abs = string_data_start + last_off
        # Read length
        length = struct.unpack_from('<H', data, last_abs)[0]
        last_abs += 2
        if length & 0x8000:
            length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, last_abs)[0]
            last_abs += 2
        last_end = last_abs + length * 2 + 2  # +2 for null terminator
        pool_end = pool + pool_size
        print(f"  last string ends at: {last_end}")
        print(f"  pool ends at: {pool_end}")
        print(f"  padding at end: {pool_end - last_end}")

    # Check all string offsets are within bounds
    out_of_bounds = 0
    for i in range(string_count):
        off = struct.unpack_from('<I', data, offset_table_start + i*4)[0]
        abs_pos = string_data_start + off
        if abs_pos < offset_table_end or abs_pos >= pool + pool_size:
            out_of_bounds += 1
            if out_of_bounds <= 3:
                print(f"  WARNING: string [{i}] offset={off} abs={abs_pos} out of bounds!")
    if out_of_bounds:
        print(f"  Total out-of-bounds strings: {out_of_bounds}")
    else:
        print(f"  All {string_count} string offsets are within bounds")

    # Check 4-byte alignment of all string data positions
    misaligned = 0
    for i in range(string_count):
        off = struct.unpack_from('<I', data, offset_table_start + i*4)[0]
        abs_pos = string_data_start + off
        if abs_pos % 4 != 0:
            misaligned += 1
            if misaligned <= 3:
                print(f"  WARNING: string [{i}] at {abs_pos} not 4-byte aligned")
    if misaligned:
        print(f"  Total misaligned strings: {misaligned}")
    else:
        print(f"  All string positions are 4-byte aligned")

    # Verify chunk sizes add up
    container_size = struct.unpack_from('<I', data, 4)[0]
    # Walk chunks
    pos = pool
    total = 0
    while pos + 8 <= len(data):
        t = struct.unpack_from('<H', data, pos)[0]
        h = struct.unpack_from('<H', data, pos+2)[0]
        s = struct.unpack_from('<I', data, pos+4)[0]
        total += s
        if s <= 0 or s > len(data):
            break
        pos += s
    print(f"  Container size: {container_size}")
    print(f"  Sum of chunk sizes: {total}")
    print(f"  Container header: 8 bytes")
    print(f"  Expected: 8 + chunks = {8 + total}")
    if 8 + total != container_size:
        print(f"  MISMATCH! Difference: {container_size - (8 + total)}")
    else:
        print(f"  OK: container size matches chunk sum")

    return pool, pool_size, string_count, strings_start

orig = extract_manifest('samples/com-gotenna-proag_1.6.0.apk')
mod = extract_manifest('output/protected.apk')

check_pool_integrity(orig, "ORIGINAL")
check_pool_integrity(mod, "MODIFIED")

# Now check: does the string data area between offset_table_end and strings_start contain garbage?
print("\n=== String offset table gap analysis ===")
for label, data in [("ORIG", orig), ("MOD", mod)]:
    pool = 8
    sc = struct.unpack_from('<I', data, pool+8)[0]
    ss = struct.unpack_from('<I', data, pool+20)[0]
    offset_end = pool + 28 + sc * 4
    string_start = pool + ss
    gap = string_start - offset_end
    gap_data = data[offset_end:string_start]
    print(f"\n  {label}: gap = {gap} bytes")
    print(f"    Gap hex: {gap_data.hex(' ')}")
    # Check if all zeros (expected for unused space)
    if all(b == 0 for b in gap_data):
        print(f"    All zeros - OK")
    else:
        print(f"    NON-ZERO - might be problematic")

# Verify the new string was inserted correctly
print("\n=== New string verification ===")
pool = 8
sc = struct.unpack_from('<I', mod, pool+8)[0]
ss = struct.unpack_from('<I', mod, pool+20)[0]
string_data = pool + ss
last_idx = sc - 1
last_off = struct.unpack_from('<I', mod, pool + 28 + last_idx*4)[0]
last_abs = string_data + last_off
length = struct.unpack_from('<H', mod, last_abs)[0]
last_abs += 2
if length & 0x8000:
    length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', mod, last_abs)[0]
    last_abs += 2
s = mod[last_abs:last_abs + length * 2].decode('utf-16-le', errors='replace')
print(f"  String [{last_idx}]: offset={last_off} abs={string_data+last_off} len={length} = {repr(s)}")

# Check if it's the expected StubApplication name
if 'StubApplication' in s:
    print(f"  CORRECT: new string is the stub application name")
else:
    print(f"  UNEXPECTED: last string is not StubApplication")

# Also check string 124 (the original application name)
for idx in [87, 124]:
    off = struct.unpack_from('<I', mod, pool + 28 + idx*4)[0]
    abs_pos = string_data + off
    length = struct.unpack_from('<H', mod, abs_pos)[0]
    abs_pos += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', mod, abs_pos)[0]
        abs_pos += 2
    s = mod[abs_pos:abs_pos + length * 2].decode('utf-16-le', errors='replace')
    print(f"  String [{idx}]: offset={off} abs={string_data+off} len={length} = {repr(s[:50])}")
