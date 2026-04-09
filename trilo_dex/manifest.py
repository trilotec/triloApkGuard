"""AndroidManifest.xml binary XML parsing and modification."""

import struct

from androguard.core.axml import AXMLPrinter


class ManifestError(Exception):
    pass


# AXML tag types
RES_XML_TYPE = 0x0003
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_RESOURCE_MAP_TYPE = 0x0180
RES_STRING_POOL_TYPE = 0x0001


def _parse_strings(data: bytes) -> list[bytes]:
    """Parse the string pool from AXML data.

    Returns list of raw bytes for each string.
    """
    pos = 0
    # Check header
    if len(data) < 8:
        raise ManifestError("AXML data too short for header")

    type_ = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    header_size = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    size = struct.unpack_from('<I', data, pos)[0]

    # RES_XML_TYPE (0x0003) is a container — string pool is a sub-chunk
    if type_ == RES_XML_TYPE:
        pos = 8  # Skip container header, string pool starts here

    if len(data) < pos + 8:
        raise ManifestError("AXML data too short for string pool")

    type_ = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    header_size = struct.unpack_from('<H', data, pos)[0]
    pos += 2
    pool_size = struct.unpack_from('<I', data, pos)[0]
    pos += 4

    if type_ != RES_STRING_POOL_TYPE:
        raise ManifestError(f"Expected string pool, got type 0x{type_:04x}")

    # String pool header
    string_count = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    style_count = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    flags = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    strings_offset = struct.unpack_from('<I', data, pos)[0]
    pos += 4
    styles_offset = struct.unpack_from('<I', data, pos)[0]
    pos += 4

    # String offsets
    pool_base = _get_string_pool_base(data)
    offsets = []
    for i in range(string_count):
        off = struct.unpack_from('<I', data, pos + i * 4)[0]
        offsets.append(off)

    # Read strings
    strings = []
    # AXML always uses UTF-16 regardless of flags
    utf16 = True
    # String data is at pool_base + strings_offset (not pos + strings_offset)
    string_data_base = pool_base + strings_offset
    for i in range(string_count):
        sp = string_data_base + offsets[i]
        if utf16:
            # UTF-16: 2 bytes length, then chars, then 0 terminator
            length = struct.unpack_from('<H', data, sp)[0]
            sp += 2
            if length & 0x8000:
                length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, sp)[0]
                sp += 2
            s = data[sp:sp + length * 2].decode('utf-16-le', errors='replace')
        else:
            # UTF-8: 1 byte length
            length = struct.unpack_from('B', data, sp)[0]
            sp += 1
            if length & 0x80:
                length = ((length & 0x7F) << 8) | struct.unpack_from('B', data, sp)[0]
                sp += 1
            s = data[sp:sp + length].decode('utf-8', errors='replace')
        strings.append(s.encode('utf-8'))

    return strings


def modify_axml(axml_path: str, new_app_name: str) -> None:
    """Modify android:name attribute in AndroidManifest.xml binary AXML.

    This does a surgical patch: finds the string pool entry for the old
    application class name, then replaces it in-place in the string pool.
    If the new name doesn't fit, we append it and update the reference.

    Also removes android:appComponentFactory attribute (the class lives in
    encrypted DEX and the framework tries to load it before our stub can
    decrypt anything).

    Args:
        axml_path: Path to AndroidManifest.xml (binary AXML).
        new_app_name: New application class name.
    """
    with open(axml_path, "rb") as f:
        data = bytearray(f.read())

    # Parse string pool
    strings = _parse_strings(data)

    # Find the android:name attribute string index
    # We need to find where the <application android:name="..."> value is
    # and replace the old app name with the new one

    # Parse the XML tree to find the application tag's name attribute
    base = _get_string_pool_base(data)
    container_size = struct.unpack_from('<I', data, 4)[0]

    # Walk inner chunks of the XML container (skip the container header itself)
    inner_pos = 8  # First chunk after container header
    # But the string pool IS the first inner chunk. We need to skip it.
    # String pool chunk:
    sp_type = struct.unpack_from('<H', data, inner_pos)[0]
    sp_header = struct.unpack_from('<H', data, inner_pos + 2)[0]
    sp_size = struct.unpack_from('<I', data, inner_pos + 4)[0]
    inner_pos += sp_size  # Skip string pool

    # First pass: find android namespace URI index and "name" attribute string index
    android_ns_uri = -1
    name_attr_str_idx = -1

    pos = inner_pos
    while pos < container_size - 8:
        type_ = struct.unpack_from('<H', data, pos)[0]
        header_size = struct.unpack_from('<H', data, pos + 2)[0]
        size = struct.unpack_from('<I', data, pos + 4)[0]

        if type_ == RES_XML_START_NAMESPACE_TYPE and header_size >= 16:
            prefix_idx = struct.unpack_from('<i', data, pos + 16)[0]
            uri_idx = struct.unpack_from('<i', data, pos + 20)[0]
            if prefix_idx >= 0 and uri_idx >= 0:
                prefix = strings[prefix_idx].decode('utf-8', errors='replace')
                uri = strings[uri_idx].decode('utf-8', errors='replace')
                if prefix == 'android' and 'schemas.android.com/apk/res/android' in uri:
                    android_ns_uri = uri_idx

        if type_ == RES_XML_START_ELEMENT_TYPE and header_size >= 16:
            attr_count = struct.unpack_from('<H', data, pos + 28)[0]
            attr_data_off = struct.unpack_from('<H', data, pos + 24)[0]
            attr_start = pos + attr_data_off + header_size
            for a in range(attr_count):
                ap = attr_start + a * 20
                if ap + 20 > len(data):
                    break
                aname_idx = struct.unpack_from('<I', data, ap + 4)[0]
                if 0 <= aname_idx < len(strings) and strings[aname_idx] == b'name':
                    name_attr_str_idx = aname_idx
                    break

        if size <= 0 or size > container_size:
            break
        pos += size

    # Second pass: find <application> element, patch name and remove appComponentFactory
    pos = inner_pos
    app_name_str_idx = -1

    while pos < container_size - 8:
        type_ = struct.unpack_from('<H', data, pos)[0]
        header_size = struct.unpack_from('<H', data, pos + 2)[0]
        size = struct.unpack_from('<I', data, pos + 4)[0]

        if type_ == RES_XML_START_ELEMENT_TYPE and header_size >= 16:
            elem_name_idx = struct.unpack_from('<I', data, pos + 20)[0]
            attr_count = struct.unpack_from('<H', data, pos + 28)[0]
            attr_data_off = struct.unpack_from('<H', data, pos + 24)[0]
            attr_start = pos + attr_data_off + header_size

            if 0 <= elem_name_idx < len(strings) and strings[elem_name_idx] == b'application':
                for a in range(attr_count):
                    ap = attr_start + a * 20
                    if ap + 20 > len(data):
                        break
                    attr_ns = struct.unpack_from('<I', data, ap)[0]
                    attr_name = struct.unpack_from('<I', data, ap + 4)[0]
                    raw_value = struct.unpack_from('<I', data, ap + 8)[0]

                    if attr_ns == android_ns_uri and attr_name == name_attr_str_idx:
                        app_name_str_idx = raw_value
                    elif attr_ns == android_ns_uri and 0 <= attr_name < len(strings):
                        attr_name_str = strings[attr_name].decode('utf-8', errors='replace')
                        if attr_name_str == 'appComponentFactory':
                            # Null out the attribute completely:
                            # - raw value → 0xFFFFFFFF (no string reference)
                            # - typed value → 0x00000000 (no typed data)
                            # Android's LoadedApk checks the typed value for string attrs
                            struct.pack_into('<I', data, ap + 8, 0xFFFFFFFF)
                            struct.pack_into('<I', data, ap + 12, 0x00000000)
                            struct.pack_into('<I', data, ap + 16, 0x00000000)

                if app_name_str_idx >= 0:
                    break

        if size <= 0 or size > container_size:
            break
        pos += size

    if app_name_str_idx < 0:
        # Fallback: brute-force search for common application class names
        # and replace the first string that looks like a package name in
        # a position that could be android:name on <application>
        _patch_name_by_search(data, strings, new_app_name)
        with open(axml_path, "wb") as f:
            f.write(data)
        return

    # Replace the string in the string pool
    # Strategy: append the new string to the end of the string pool,
    # then update the reference
    _append_and_patch_string(data, app_name_str_idx, new_app_name)

    with open(axml_path, "wb") as f:
        f.write(data)


def _patch_name_by_search(data: bytearray, strings: list[bytes], new_app_name: str) -> None:
    """Fallback: search for likely android:name string values and replace."""
    # Look for strings that look like class names (contain dots, start with letter)
    for i, s in enumerate(strings):
        text = s.decode('utf-8', errors='replace')
        # Skip common non-class-name strings
        if ('.' in text and
            not text.startswith('android.') and
            not text.startswith('com.android.') and
            len(text) > 5 and
            text[0].isalpha()):
            # This might be the application class name
            # Replace it
            _replace_string_in_pool(data, i, new_app_name)
            return

    # Last resort: search for any string with '.' that could be app name
    for i, s in enumerate(strings):
        text = s.decode('utf-8', errors='replace')
        if '.' in text and len(text) > 3:
            _replace_string_in_pool(data, i, new_app_name)
            return

    raise ManifestError("Could not find application class name in manifest")


def _replace_string_in_pool(data: bytearray, str_idx: int, new_str: str) -> None:
    """Replace a string in the pool if it fits (same or shorter length).

    For longer strings, we append to the pool and patch the reference.
    """
    new_bytes = new_str.encode('utf-16-le')
    old = _get_string_bytes(data, str_idx)

    if len(new_bytes) <= len(old):
        # In-place replacement (pad with nulls if shorter)
        offset = _find_string_offset(data, str_idx)
        if offset is not None:
            # Check if UTF-8 or UTF-16
            first_byte = data[offset]
            if first_byte & 0x80:
                # UTF-8 with extended length
                offset += 2
            else:
                offset += 1
            # Write new bytes + null terminator
            for j in range(len(old)):
                if j < len(new_bytes):
                    data[offset + j] = new_bytes[j]
                else:
                    data[offset + j] = 0
    else:
        # Need to append - find a suitable location and patch
        _append_and_patch_string(data, str_idx, new_str)


def _get_string_bytes(data: bytes, str_idx: int) -> bytes:
    """Get the raw bytes of a string from the pool."""
    offset = _find_string_offset(data, str_idx)
    if offset is None:
        return b''
    # UTF-16 length
    length = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, offset)[0]
        offset += 2
    return data[offset:offset + length * 2]


def _get_string_pool_base(data: bytes) -> int:
    """Return the byte offset where the string pool chunk starts.

    AXML files start with a RES_XML_TYPE container (8 bytes) followed by
    the string pool chunk.  If the file starts directly with the string
    pool we return 0.
    """
    if len(data) < 16:
        return 0
    type_ = struct.unpack_from('<H', data, 0)[0]
    if type_ == RES_XML_TYPE:
        return 8
    return 0


def _find_string_offset(data: bytes, str_idx: int) -> int | None:
    """Find the byte offset of a string in the pool."""
    base = _get_string_pool_base(data)
    if len(data) < base + 28:
        return None

    string_count = struct.unpack_from('<I', data, base + 8)[0]
    strings_offset = struct.unpack_from('<I', data, base + 20)[0]

    if str_idx >= string_count:
        return None

    offset_entry = base + 28 + str_idx * 4
    if offset_entry + 4 > len(data):
        return None

    str_offset = struct.unpack_from('<I', data, offset_entry)[0]
    return base + 28 + string_count * 4 + str_offset


def _append_and_patch_string(data: bytearray, str_idx: int, new_str: str) -> None:
    """Append a new string to the string pool and patch all references.

    The new string is placed at the end of the string data area (after all
    existing strings), and a new offset entry is added to the offset table.
    All references to str_idx are updated to point to the new index.
    """
    new_bytes = new_str.encode('utf-16-le')
    base = _get_string_pool_base(data)

    string_count = struct.unpack_from('<I', data, base + 8)[0]
    strings_offset = struct.unpack_from('<I', data, base + 20)[0]
    styles_offset = struct.unpack_from('<I', data, base + 24)[0]
    pool_size = struct.unpack_from('<I', data, base + 4)[0]

    # String data area starts at base + 28 + string_count * 4
    # The offset table occupies base + 28 .. base + 28 + string_count*4 - 1
    string_data_start = base + 28 + string_count * 4

    # Find the end of the string data (where last string ends)
    last_str_offset_entry = base + 28 + (string_count - 1) * 4
    last_str_rel_offset = struct.unpack_from('<I', data, last_str_offset_entry)[0]
    last_str_abs = string_data_start + last_str_rel_offset
    last_len = struct.unpack_from('<H', data, last_str_abs)[0]
    last_str_abs += 2
    if last_len & 0x8000:
        last_len = ((last_len & 0x7FFF) << 16) | struct.unpack_from('<H', data, last_str_abs)[0]
        last_str_abs += 2
    last_end = last_str_abs + last_len * 2

    # Build new string entry (UTF-16)
    if len(new_bytes) // 2 < 0x8000:
        new_entry = struct.pack('<H', len(new_bytes) // 2) + new_bytes + b'\x00\x00'
    else:
        slen = len(new_bytes) // 2
        b1 = 0x8000 | (slen & 0x7FFF)
        b2 = (slen >> 16) & 0xFFFF
        new_entry = struct.pack('<HH', b1, b2) + new_bytes + b'\x00\x00\x00\x00'

    # Align new entry to 4 bytes
    pad = (4 - (last_end % 4)) % 4
    padding = b'\x00' * pad

    # Step 1: Insert new offset entry at end of offset table
    # This shifts everything after offset_table_end by 4 bytes
    offset_table_end = base + 28 + string_count * 4

    # Step 2: Calculate insert position for string data (after offset table insertion)
    # The string data and offset_table_end both shift by 4
    new_string_data_start = string_data_start + 4
    insert_pos = last_end + pad + 4  # +4 because offset table was inserted before

    # New relative offset (relative to new string_data_start)
    # The string entry starts after the padding
    new_rel_offset = insert_pos + len(padding) - new_string_data_start

    # Insert offset entry
    data[offset_table_end:offset_table_end] = struct.pack('<I', new_rel_offset)

    # Step 3: Insert new string data
    data[insert_pos:insert_pos] = padding + new_entry

    # Update string count
    struct.pack_into('<I', data, base + 8, string_count + 1)

    # Update pool chunk size (new entry + padding + 4 bytes for offset entry)
    added = len(new_entry) + len(padding) + 4
    struct.pack_into('<I', data, base + 4, pool_size + added)

    # Update container size
    if base > 0:
        cs = struct.unpack_from('<I', data, 4)[0]
        struct.pack_into('<I', data, 4, cs + added)

    # Update strings_start (offset table grew by 4 bytes)
    struct.pack_into('<I', data, base + 20, strings_offset + 4)

    # Update styles_start if present
    if styles_offset > 0:
        struct.pack_into('<I', data, base + 24, styles_offset + added)

    # Patch all references from old index to new index
    new_str_idx = string_count
    _patch_string_references(data, str_idx, new_str_idx)

    # ── 4-byte alignment fix ──
    # Android's AXML parser requires the string data area to be a multiple
    # of 4 bytes. After insertion, check and add padding if needed.
    new_pool_size = struct.unpack_from('<I', data, base + 4)[0]
    new_strings_start = struct.unpack_from('<I', data, base + 20)[0]
    string_data_size = new_pool_size - new_strings_start
    alignment = string_data_size % 4
    if alignment != 0:
        align_pad = 4 - alignment
        # Insert padding at the end of the pool (before next chunk)
        pool_end = base + new_pool_size
        data[pool_end:pool_end] = b'\x00' * align_pad
        # Update pool chunk size and container size
        struct.pack_into('<I', data, base + 4, new_pool_size + align_pad)
        if base > 0:
            cs = struct.unpack_from('<I', data, 4)[0]
            struct.pack_into('<I', data, 4, cs + align_pad)


def _truncate_and_replace(data: bytearray, str_idx: int, new_bytes: bytes) -> None:
    """Truncate new string to fit in-place (for when append is not possible)."""
    offset = _find_string_offset(data, str_idx)
    if offset is None:
        return
    # UTF-16 length
    length = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if length & 0x8000:
        length = ((length & 0x7FFF) << 16) | struct.unpack_from('<H', data, offset)[0]
        offset += 2
    max_len = length  # in UTF-16 code units
    new_len = len(new_bytes) // 2
    if new_len > max_len:
        new_bytes = new_bytes[:max_len * 2]
    for j in range(len(new_bytes)):
        data[offset + j] = new_bytes[j]


def _patch_string_references(data: bytearray, old_idx: int, new_idx: int) -> None:
    """Replace all references to old_idx with new_idx in the AXML data.

    Updates both the raw value (+8) and the typed value (+12, +16) for
    string-type attributes, since Android's framework reads the typed
    value rather than the raw value for string references.
    """
    import struct as st

    base = _get_string_pool_base(data)
    container_size = st.unpack_from('<I', data, 4)[0]
    sp_size = st.unpack_from('<I', data, base + 4)[0]
    pos = base + sp_size  # Skip string pool

    while pos < container_size - 8:
        type_ = st.unpack_from('<H', data, pos)[0]
        header_size = st.unpack_from('<H', data, pos + 2)[0]
        size = st.unpack_from('<I', data, pos + 4)[0]

        if type_ == RES_XML_START_ELEMENT_TYPE and header_size >= 16:
            attr_count = st.unpack_from('<H', data, pos + 28)[0]
            attr_data_off = st.unpack_from('<H', data, pos + 24)[0]
            attr_start = pos + attr_data_off + header_size
            for a in range(attr_count):
                ap = attr_start + a * 20
                if ap + 20 > len(data):
                    break
                raw_val = st.unpack_from('<I', data, ap + 8)[0]
                typed_val = st.unpack_from('<I', data, ap + 12)[0]
                typed_data = st.unpack_from('<I', data, ap + 16)[0]

                # Patch raw value
                if raw_val == old_idx:
                    st.pack_into('<I', data, ap + 8, new_idx)

                # Patch typed value data field (offset +16)
                if typed_data == old_idx:
                    st.pack_into('<I', data, ap + 16, new_idx)
                    # Also update the packed typed value at +12
                    # Format: (data << 8) | dataType, dataType=0x03 for strings
                    st.pack_into('<I', data, ap + 12, (new_idx << 8) | 0x03)

        if type_ == 0:
            break

        pos += size


def parse_axml(axml_path: str):
    """Parse binary AXML and return ElementTree root (for information extraction)."""
    with open(axml_path, "rb") as f:
        raw = f.read()

    printer = AXMLPrinter(raw)
    root = printer.get_xml_obj()

    if root is None:
        raise ManifestError("Failed to parse AndroidManifest.xml")

    return root


def modify_application_name(root, new_app_name: str) -> None:
    """Modify android:name attribute of <application> tag in ElementTree root."""
    import xml.etree.ElementTree as ET
    ANDROID_NS = "http://schemas.android.com/apk/res/android"
    app_elem = root.find("application")
    if app_elem is None:
        raise ManifestError("<application> tag not found in AndroidManifest.xml")
    name_attr = f"{{{ANDROID_NS}}}name"
    app_elem.set(name_attr, new_app_name)


def serialize_axml(root) -> str:
    """Serialize ElementTree to text XML."""
    import xml.etree.ElementTree as ET
    return ET.tostring(root, encoding="unicode", xml_declaration=False)


def compile_axml(xml_text: str, output_path: str, sdk_dir: str) -> None:
    """This function is deprecated. Use modify_axml() directly instead.

    Kept for API compatibility.
    """
    raise ManifestError("compile_axml is deprecated. Use modify_axml() for direct binary patching.")
