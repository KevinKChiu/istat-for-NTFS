import datetime
from textwrap import dedent


def attr_to_string(type_code: int, size: int, init_size=None) -> str:
    """Convert an attribute to a string.

    input:
        type_code: int, the type code of the attribute
        size: int, the size of the attribute
        init_size: int, the size of the attribute before it was compressed
    output:
        str: the string representation of the attribute

    """
    type_name = {
        0x10: "$STANDARD_INFORMATION (16-0)",
        0x30: "$FILE_NAME (48-3)",
        0x80: "$DATA (128-2)",
    }[type_code]

    if init_size:
        format_str = (
            f"Type: {type_name}   Name: N/A   " f"Non-Resident   size: {size}  init_size: {init_size}"
        )
    else:
        format_str = f"Type: {type_name}   Name: N/A   Resident   size: {size}\n"
    return format_str


def unpack(data: bytes, signed=False, byteorder="little") -> int:
    """Unpack a single value from bytes"""
    return int.from_bytes(data, byteorder=byteorder, signed=signed)


def get_attr_by_id(attr_id: int, entry: bytes, prev_attr_end: int) -> tuple[bytes, int]:
    """Extract the bytes for an attribute specified by its ID type.

    input:
        attr_id: int, the ID of the attribute to extract (e.g., std_info is 0x38)
        entry: bytes, the MFT entry to extract from
        prev_attr_end: int, the offset of the previous attribute
    output (tuple):
        bytes: the bytes of the attribute
        int: the offset of the next attribute
    """

    # set to NULLs to force us through the while loop at least once
    attr_full_entry = b"\x00\x00\x00\x00"

    curr_attr_end = prev_attr_end
    # starting from the previous attribute, find the given attr_id
    # the attr_id is kept in the first four bytes of the entry
    while unpack(attr_full_entry[:4]) != attr_id:
        # we didn't find, move to the next attribute
        attr_start = prev_attr_end
        length = unpack(entry[attr_start + 4 : attr_start + 8])
        curr_attr_end = attr_start + length
        attr_full_entry = entry[attr_start:curr_attr_end]
        prev_attr_end = curr_attr_end
    return attr_full_entry, curr_attr_end


def flag_dump(value: int) -> str:
    """Convert NTFS attribute flags to strings."""
    string = ""
    if value & 0x0001:
        string = string + "Read Only "
    if value & 0x0002:
        string = string + "Hidden "
    if value & 0x0004:
        string = string + "System "
    if value & 0x0020:
        string = string + "Archive "
    if value & 0x0040:
        string = string + "Device "
    if value & 0x0080:
        string = string + "Normal "
    if value & 0x0100:
        string = string + "Temporary "
    if value & 0x0200:
        string = string + "Sparse file "
    if value & 0x0400:
        string = string + "Reparse point "
    if value & 0x0800:
        string = string + "Compressed "
    if value & 0x1000:
        string = string + "Offline "
    if value & 0x2000:
        string = string + "Not indexed "
    if value & 0x4000:
        string = string + "Encrypted "
    if string == "":
        string = str(hex(value) + " (Unknown flag)")
    return string


def apply_fixup(entry: bytes) -> bytes:
    """Apply the fixup array to an MFT entry"""
    assert entry[0:4] == b"FILE"
    fixup = int.from_bytes(entry[4:6], "little")
    num_fixup_entries = int.from_bytes(entry[6:8], "little")
    fixuprepl = entry[fixup + 2 : fixup + 2 * num_fixup_entries]
    entry = entry[:510] + fixuprepl[0:2] + entry[512:1022] + fixuprepl[2:4]
    return entry


def header_to_str(header: dict) -> str:
    """Convert a header dict into a string"""
    output = dedent(
        f"""        MFT Entry Header Values:
        Entry: {header['address']}        Sequence: {header['sequence']}
        $LogFile Sequence Number: {header['logfile_seq_num']}
        {"Allocated" if header['allocated'] else "Unallocated"} File
        Links: {header['links']}
    """
    )
    return output


def std_info_to_str(std_info: dict) -> str:
    """Convert a standard info dict into a string"""
    output = dedent(
        f"""
        $STANDARD_INFORMATION Attribute Values:
        Flags: {flag_dump(std_info['flags'])}
        Owner ID: {0}
        Created:\t{std_info['created']}
        File Modified:\t{std_info['modified']}
        MFT Modified:\t{std_info['mft_modified']}
        Accessed:\t{std_info['accessed']}
        """
    )
    return output


def file_name_to_str(file_name: dict) -> str:
    """Convert a file name dict into a string"""
    output = dedent(
        f"""
        $FILE_NAME Attribute Values:
        Flags: {flag_dump(file_name['flags'])}
        Name: {file_name['name']}
        Parent MFT Entry: {file_name['parent']:<6} Sequence: {file_name['sequence']}
        Allocated Size: {file_name['allocated_size']:<8} Actual Size: {file_name['actual_size']}
        Created:\t{file_name['created']}
        File Modified:\t{file_name['modified']}
        MFT Modified:\t{file_name['mft_modified']}
        Accessed:\t{file_name['accessed']}
    """
    )
    return output


def _localtime_string(windows_timestamp: int) -> str:
    """
    Convert a windows timestamp into istat-compatible output.

    Assumes your local host is in the EDT timezone.

    :param windows_timestamp: the struct.decoded 8-byte windows timestamp
    :return: an istat-compatible string representation of this time in EDT
    """
    epoch_ts = (windows_timestamp - 116444736000000000) / 10000000
    if windows_timestamp > 0:
        dt = datetime.datetime.fromtimestamp(epoch_ts)
    else:
        dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=int(epoch_ts))

    hms = dt.strftime("%Y-%m-%d %H:%M:%S")
    fraction = windows_timestamp % 10000000
    return f"{hms}.{fraction:07d}00 (EDT)"


def parse_time(attribute: bytes, index_range: tuple) -> str:
    """Convert windows timestamps into strings

    input:
        entry: the full attribute including its header
        index_range: the range of bytes to read from the attribute; e.g.,  (10, 20)
    output:
        a string representation of the time
    """
    header_length = 24
    time_value = int.from_bytes(
        attribute[header_length + index_range[0] : header_length + index_range[1]],
        byteorder="little",
        signed=False,
    )
    return _localtime_string(time_value)
