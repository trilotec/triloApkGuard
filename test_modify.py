"""Test manifest modification in isolation."""
import struct
import tempfile
import os
import sys

sys.path.insert(0, '.')

from trilo_dex.manifest import modify_axml, _parse_strings, _get_string_pool_base
import zipfile

# Extract original manifest
with zipfile.ZipFile('samples/com-gotenna-proag_1.6.0.apk') as zf:
    orig_data = zf.read('AndroidManifest.xml')

print(f"Original manifest: {len(orig_data)} bytes")

# Write to temp file
with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
    f.write(orig_data)
    tmp_path = f.name

# Modify it
modify_axml(tmp_path, "com.trilo.stub.StubApplication")

# Read back
with open(tmp_path, 'rb') as f:
    mod_data = f.read()

os.unlink(tmp_path)

print(f"Modified manifest: {len(mod_data)} bytes")
print(f"Size difference: {len(mod_data) - len(orig_data)} bytes")

# Verify structure
print("\n=== String pool ===")
for label, data in [("ORIG", orig_data), ("MOD", mod_data)]:
    pool = _get_string_pool_base(data)
    sc = struct.unpack_from('<I', data, pool + 8)[0]
    ss = struct.unpack_from('<I', data, pool + 20)[0]
    ps = struct.unpack_from('<I', data, pool + 4)[0]
    print(f"  {label}: base={pool} count={sc} stringsStart={ss} pool_size={ps} data_end={pool+ps}")

# Parse strings to verify they're readable
print("\n=== String parsing ===")
try:
    strings = _parse_strings(mod_data)
    print(f"  Successfully parsed {len(strings)} strings")
    # Check the new string
    for i, s in enumerate(strings):
        if b'StubApplication' in s:
            print(f"  Found stub string at index [{i}]: {s.decode('utf-8', errors='replace')}")
except Exception as e:
    print(f"  ERROR parsing strings: {e}")

# Verify the application element's android:name
print("\n=== Application element check ===")
pool = _get_string_pool_base(mod_data)
sc = struct.unpack_from('<I', mod_data, pool + 8)[0]
container_size = struct.unpack_from('<I', mod_data, 4)[0]

# Skip string pool
sp_size = struct.unpack_from('<I', mod_data, pool + 4)[0]
pos = pool + sp_size

while pos < container_size - 8:
    type_ = struct.unpack_from('<H', mod_data, pos)[0]
    header_size = struct.unpack_from('<H', mod_data, pos + 2)[0]
    size = struct.unpack_from('<I', mod_data, pos + 4)[0]

    if type_ == 0x0102:  # START_ELEMENT
        elem_name_off = struct.unpack_from('<I', mod_data, pos + 20)[0]
        attr_count = struct.unpack_from('<H', mod_data, pos + 28)[0]
        attr_data_off = struct.unpack_from('<H', mod_data, pos + 24)[0]

        # Get element name
        strings_start = struct.unpack_from('<I', mod_data, pool + 20)[0]
        string_data_base = pool + strings_start
        name_rel = struct.unpack_from('<I', mod_data, pool + 28 + elem_name_off//4)[0] if elem_name_off < sc else elem_name_off

        # Actually, elem_name_off is a string index, not a byte offset
        elem_name_idx = elem_name_off
        if 0 <= elem_name_idx < len(strings):
            elem_name = strings[elem_name_idx].decode('utf-8', errors='replace')
        else:
            elem_name = f"[idx={elem_name_idx}]"

        if elem_name == 'application':
            print(f"  Found <application> at pos {pos}")
            print(f"  Element name index: {elem_name_idx}")
            print(f"  Attribute count: {attr_count}")
            print(f"  Attribute data offset: {attr_data_off}")

            attr_start = pos + attr_data_off + header_size
            for a in range(attr_count):
                ap = attr_start + a * 20
                if ap + 20 > len(mod_data):
                    break
                ns = struct.unpack_from('<I', mod_data, ap)[0]
                name = struct.unpack_from('<I', mod_data, ap + 4)[0]
                raw = struct.unpack_from('<I', mod_data, ap + 8)[0]
                typed0 = struct.unpack_from('<I', mod_data, ap + 12)[0]
                typed1 = struct.unpack_from('<I', mod_data, ap + 16)[0]

                ns_str = strings[ns].decode('utf-8', errors='replace') if 0 <= ns < len(strings) else f"[{ns}]"
                name_str = strings[name].decode('utf-8', errors='replace') if 0 <= name < len(strings) else f"[{name}]"
                raw_str = strings[raw].decode('utf-8', errors='replace') if 0 <= raw < len(strings) else f"[{raw}]"

                if name_str == 'name' and 'android' in ns_str:
                    print(f"  attr[{a}] android:name -> raw={raw} -> '{raw_str}'")
                    if raw == sc - 1:
                        print(f"    CORRECT: points to new string index {sc-1}")
                    else:
                        print(f"    WARNING: should point to {sc-1}, but points to {raw}")
        elif elem_name == 'manifest':
            print(f"  Found <manifest> at pos {pos}")

    if size <= 0 or size > container_size:
        break
    pos += size

# Try to parse with androguard
print("\n=== Androguard parsing ===")
try:
    from androguard.core.axml import AXMLPrinter
    printer = AXMLPrinter(mod_data)
    root = printer.get_xml_obj()
    if root is not None:
        print(f"  Androguard successfully parsed the manifest")
        print(f"  Root tag: {root.tag}")
        app = root.find("application")
        if app is not None:
            ns = "http://schemas.android.com/apk/res/android"
            name = app.get(f"{{{ns}}}name")
            print(f"  application android:name: {name}")
        else:
            print(f"  WARNING: <application> not found in parsed XML")
    else:
        print(f"  ERROR: AXMLPrinter returned None - manifest is corrupted!")
except Exception as e:
    print(f"  ERROR: {e}")

# Write modified manifest for further testing
with open('output/test_modified_manifest.xml', 'wb') as f:
    f.write(mod_data)
print(f"\nWrote modified manifest to output/test_modified_manifest.xml")
