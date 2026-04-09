import struct
import zipfile
import sys

def extract_manifest(apk_path):
    with zipfile.ZipFile(apk_path) as zf:
        return zf.read('AndroidManifest.xml')

def dump_axml_structure(data, label=""):
    """Dump the full AXML structure for debugging."""
    print(f"\n=== {label} (total {len(data)} bytes) ===")

    pos = 0
    # Container header
    type_ = struct.unpack_from('<H', data, 0)[0]
    header_size = struct.unpack_from('<H', data, 2)[0]
    size = struct.unpack_from('<I', data, 4)[0]
    print(f"Container: type=0x{type_:04x} header={header_size} size={size}")

    if type_ == 0x0003:  # RES_XML_TYPE
        pos = 8
    else:
        pos = 0

    chunk_num = 0
    elem_count = 0
    while pos + 8 <= len(data):
        type_ = struct.unpack_from('<H', data, pos)[0]
        header_size = struct.unpack_from('<H', data, pos + 2)[0]
        size = struct.unpack_from('<I', data, pos + 4)[0]

        type_names = {
            0x0001: "STRING_POOL",
            0x0100: "START_NS",
            0x0101: "END_NS",
            0x0102: "START_ELEM",
            0x0103: "END_ELEM",
            0x0180: "RESOURCE_MAP",
        }
        tname = type_names.get(type_, f"UNKNOWN(0x{type_:04x})")

        if type_ == 0x0001:
            string_count = struct.unpack_from('<I', data, pos + 8)[0]
            strings_start = struct.unpack_from('<I', data, pos + 20)[0]
            print(f"  [{chunk_num:2d}] pos={pos:6d} {tname:16s} size={size:6d} strings={string_count} stringsStart={strings_start}")
        elif type_ == 0x0180:
            n_resources = (size - 8) // 4
            print(f"  [{chunk_num:2d}] pos={pos:6d} {tname:16s} size={size:6d} resources={n_resources}")
        elif type_ == 0x0102:
            elem_name_idx = struct.unpack_from('<I', data, pos + 20)[0]
            attr_count = struct.unpack_from('<H', data, pos + 28)[0]
            attr_data_off = struct.unpack_from('<H', data, pos + 24)[0]
            elem_count += 1
            print(f"  [{chunk_num:2d}] pos={pos:6d} {tname:16s} size={size:6d} name_idx={elem_name_idx} attrs={attr_count} attrDataOff={attr_data_off}")

            # Dump attribute data
            attr_start = pos + attr_data_off + header_size
            for a in range(attr_count):
                ap = attr_start + a * 20
                if ap + 20 > len(data):
                    break
                ns = struct.unpack_from('<I', data, ap)[0]
                name = struct.unpack_from('<I', data, ap + 4)[0]
                raw = struct.unpack_from('<I', data, ap + 8)[0]
                typed0 = struct.unpack_from('<I', data, ap + 12)[0]
                typed1 = struct.unpack_from('<I', data, ap + 16)[0]
                print(f"         attr[{a}]: ns={ns} name={name} raw={raw} typed={typed0:08x} {typed1:08x}")
        elif type_ == 0x0100:
            prefix = struct.unpack_from('<i', data, pos + 16)[0]
            uri = struct.unpack_from('<i', data, pos + 20)[0]
            print(f"  [{chunk_num:2d}] pos={pos:6d} {tname:16s} size={size:6d} prefix={prefix} uri={uri}")
        elif type_ == 0x0103:
            elem_name_idx = struct.unpack_from('<I', data, pos + 20)[0]
            print(f"  [{chunk_num:2d}] pos={pos:6d} {tname:16s} size={size:6d} name_idx={elem_name_idx}")
        else:
            print(f"  [{chunk_num:2d}] pos={pos:6d} {tname:16s} size={size:6d}")

        if size <= 0 or size > len(data):
            print(f"    ** invalid size, stopping **")
            break

        pos += size
        chunk_num += 1

def dump_strings(data, pool_base, indices, string_pool_pos):
    """Dump specific string indices from the pool."""
    string_count = struct.unpack_from('<I', data, pool_base + 8)[0]
    strings_offset = struct.unpack_from('<I', data, pool_base + 20)[0]
    string_data_base = pool_base + strings_offset

    for idx in indices:
        if idx < 0 or idx >= string_count:
            print(f"  [{idx}] OUT OF RANGE (count={string_count})")
            continue
        off = struct.unpack_from('<I', data, pool_base + 28 + idx * 4)[0]
        abs_pos = string_data_base + off
        length = struct.unpack_from('<H', data, abs_pos)[0]
        abs_pos += 2
        if length & 0x8000:
            length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, abs_pos)[0]
            abs_pos += 2
        s = data[abs_pos:abs_pos + length * 2].decode('utf-16-le', errors='replace')
        print(f"  [{idx:3d}] rel={off:5d} abs={string_data_base+off:5d} len={length:3d} {repr(s[:60])}")


def compare_byte_level(orig, mod):
    """Find all byte-level differences."""
    print(f"\n=== Byte-level comparison ===")
    print(f"Original: {len(orig)} bytes")
    print(f"Modified: {len(mod)} bytes")

    # Find first difference
    min_len = min(len(orig), len(mod))
    diffs = []
    for i in range(min_len):
        if orig[i] != mod[i]:
            diffs.append(i)

    print(f"First {min_len} bytes: {len(diffs)} differences")

    # Show difference regions
    if diffs:
        # Group into regions
        regions = []
        start = diffs[0]
        prev = diffs[0]
        for d in diffs[1:]:
            if d - prev > 10:
                regions.append((start, prev))
                start = d
            prev = d
        regions.append((start, prev))

        for rs, re in regions[:20]:
            context = 20
            print(f"\n  Diff region: bytes {rs}-{re} ({re-rs+1} bytes differ)")
            print(f"  ORIG[{rs-context:6d}:{rs+context:6d}]: {orig[rs-context:rs+context].hex(' ')}")
            print(f"  MOD [{rs-context:6d}:{rs+context:6d}]: {mod[rs-context:rs+context].hex(' ')}")


orig_path = 'samples/com-gotenna-proag_1.6.0.apk'
mod_path = 'output/protected.apk'

orig_data = extract_manifest(orig_path)
mod_data = extract_manifest(mod_path)

# Dump structures
dump_axml_structure(orig_data, "ORIGINAL")
dump_axml_structure(mod_data, "MODIFIED")

# Compare
compare_byte_level(orig_data, mod_data)

# Now let's specifically check: after the 4-byte offset insertion at 668,
# and the 66-byte string insertion, does the RESOURCE_MAP count still match?
# And are the attribute bytes identical (except for the patched raw value)?

print("\n=== Specific checks ===")

# Check string pool headers
for label, d in [("ORIG", orig_data), ("MOD", mod_data)]:
    pool_base = 8
    sc = struct.unpack_from('<I', d, pool_base + 8)[0]
    ss = struct.unpack_from('<I', d, pool_base + 20)[0]
    sty = struct.unpack_from('<I', d, pool_base + 24)[0]
    ps = struct.unpack_from('<I', d, pool_base + 4)[0]
    print(f"  {label}: string_count={sc} stringsStart={ss} stylesStart={sty} pool_size={ps}")
