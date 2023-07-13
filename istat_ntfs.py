import argparse

from hw5utils import (
    apply_fixup,
    attr_to_string,
    file_name_to_str,
    get_attr_by_id,
    header_to_str,
    parse_time,
    std_info_to_str,
    unpack,
)


class ParseMFT:
    def __init__(self, file):
        self.file = file
        self.file.seek(0)
        boot = self.file.read(512)
        bytes_per_sector = unpack(boot[11:13])
        sectors_per_cluster = unpack(boot[13:14])
        mft_start = unpack(boot[48:56])
        self.bytes_per_entry = 1024  # hard coded
        self.mft_byte_offset = mft_start * sectors_per_cluster * bytes_per_sector

    def parse_entry_header(self, address: int, entry: bytes) -> dict:
        """Parse the header of the MFT entry.

        input:
            address: the address of the entry
            entry: the bytes of the entry
        returns:
            dict: {
                'address': int, (same as input)
                'sequence': int, (the sequence value)
                'logfile_seq_num': int, (the log sequence number)
                'links': int, (the link count)
                'allocated': bool, (whether the entry is allocated)
            }

        """
        # fill this in
        header_dict = {}
        header_dict["address"] = address
        header_dict["sequence"] = unpack(entry[16:18])
        header_dict["logfile_seq_num"] = unpack(entry[8:16])
        header_dict["links"] = unpack(entry[18:20])
        flag = unpack(entry[22:24])
        header_dict["allocated"] = flag != 0
        return header_dict

    def parse_std_info_attr(self, entry: bytes, entry_start: int = 0x38) -> dict:
        """Parse the standard_information attribute of an MFT entry.

        input:
            entry: bytes, the MFT entry to parse
            entry_start: int, the offset of the first byte of the attribute
        output:
            dict{
                'created': int, (the creation time)
                'modified': int, (the modification time)
                'mft_modified': int, (the MFT modified time)
                'accessed': int, (the last access time)
                'flags': int, (the flags)
                'std_info_size': int, (the size of the attribute)
                'std_info_end': int, (the offset of the next attribute)
            }
        """

        attribute, std_info_end = get_attr_by_id(0x10, entry, entry_start)
        # fill this in
        std_info_dict = {}
        content_offset = unpack(attribute[20:22])
        content = attribute[content_offset : std_info_end + 1]
        std_info_dict["created"] = parse_time(attribute, (0, 8))
        std_info_dict["modified"] = parse_time(attribute, (8, 16))
        std_info_dict["mft_modified"] = parse_time(attribute, (16, 24))
        std_info_dict["accessed"] = parse_time(attribute, (24, 32))
        std_info_dict["flags"] = unpack(content[32:36])
        std_info_dict["std_info_size"] = unpack(attribute[16:20])
        std_info_dict["std_info_end"] = std_info_end
        return std_info_dict

    def parse_file_name_attr(self, entry: bytes, prev_entry_end: int) -> dict:
        """Parse the file_name attribute of an MFT entry.

        input:
            entry: bytes, the MFT entry to parse
            prev_entry_end: int, the offset of the last byte of the previous attribute
        output:
            dict{
                'name': str, (the name of the file)
                'parent': int, (the parent directory)
                'sequence': int, (the sequence number)
                'allocated_size': int, (the allocated size)
                'actual_size': int, (the actual size)
                'created': int, (the creation time)
                'modified': int, (the modification time)
                'mft_modified': int, (the MFT modified time)
                'accessed': int, (the last access time)
                'flags': int, (the flags)
                'file_name_size': int, (the size of the attribute)
                'file_name_end': int, (the offset of the next attribute)
            }
        """
        attribute, file_name_end = get_attr_by_id(0x30, entry, prev_entry_end)
        # fill this in
        file_name_dict = {}
        content_offset = unpack(attribute[20:22])
        content = attribute[content_offset : file_name_end + 1]
        # file_name_dict["parent"] = unpack(content[2:8])
        file_name_dict["parent"] = unpack(content[0:6])
        file_name_dict["sequence"] = unpack(content[6:8])
        file_name_dict["allocated_size"] = unpack(content[40:48])
        file_name_dict["actual_size"] = unpack(content[48:56])
        file_name_dict["created"] = parse_time(attribute, (8, 16))
        file_name_dict["modified"] = parse_time(attribute, (16, 24))
        file_name_dict["mft_modified"] = parse_time(attribute, (24, 32))
        file_name_dict["accessed"] = parse_time(attribute, (32, 40))
        file_name_dict["flags"] = unpack(content[56:60])
        file_name_dict["file_name_size"] = unpack(attribute[16:20])
        file_name_dict["name"] = content[66 : 66 + (content[64] * 2)].decode("utf-16-le")
        file_name_dict["file_name_end"] = file_name_end
        return file_name_dict

    def parse_data_attr(self, entry: bytes, prev_attr_end: int) -> dict:
        """Parse the data attribute of an MFT entry.

        input:
            entry: bytes, the MFT entry to parse
            prev_attr_end: int, the offset of the last byte of the previous attribute
        output:
            if the entry is resident:
            dict:
                type: 0x80, (the type code of the attribute)
                size: int, (the size of the attribute)

            if the entry is non-resident, the follow keys are added:
                init_size: int, (the size of the attribute before it was compressed)
                sector_list: list, (the list of non-resident sectors)

        """
        attribute, _ = get_attr_by_id(0x80, entry, prev_attr_end)
        # fill this in
        data_dict = {}
        data_dict["type"] = 0x80
        non_res_flag = attribute[8]
        if non_res_flag == 0:
            data_dict["size"] = unpack(attribute[16:20])
        else:
            data_dict["size"] = unpack(attribute[48:56])
            data_dict["init_size"] = unpack(attribute[56:63])
            sector_list = []
            runlist_offset = unpack(attribute[32:34])
            first_byte = attribute[runlist_offset]
            prev_first_cluster = 0
            while first_byte != 0:
                first_nibble = format(unpack(attribute[runlist_offset : runlist_offset + 1]), "08b")[0:4]
                second_nibble = format(unpack(attribute[runlist_offset : runlist_offset + 1]), "08b")[4:8]
                offset_nibble = int(first_nibble, 2)
                run_length_nibble = int(second_nibble, 2)
                byte_offset = runlist_offset + run_length_nibble + 1
                length = unpack(attribute[runlist_offset + 1 : byte_offset], True)
                cluster = unpack(attribute[byte_offset : byte_offset + offset_nibble], True)
                prev_first_cluster += cluster
                curr_sec_list = list(range(prev_first_cluster, prev_first_cluster + length))
                sector_list += curr_sec_list
                runlist_offset = byte_offset + offset_nibble
                first_byte = attribute[runlist_offset]
            data_dict["sector_list"] = sector_list
        return data_dict

    def istat_entry(self, address: int) -> dict:
        """Parse the header, std_info, file_name, and data attributes of an MFT entry.

        input:
            address: int, the address of the MFT entry (e.g., 0 is the MFT itself)
        output:
            dict:
                'header': dict, from parse_entry_header()
                'std_info': dict, from parse_std_info()
                'file_name': dict, from parse_file_name()
                'data': dict, from parse_data_attr()
        """
        # assumes contiguous MFT
        self.file.seek(self.mft_byte_offset + address * self.bytes_per_entry)
        entry = self.file.read(1024)
        entry = apply_fixup(entry)

        # fill this in
        # parse the header
        # parse std_info attribute
        # parse filename attribute
        # parse the data attribute
        mft_entry_dict = {}
        mft_entry_dict["header"] = self.parse_entry_header(address, entry)
        mft_entry_dict["std_info"] = self.parse_std_info_attr(entry)
        mft_entry_dict["file_name"] = self.parse_file_name_attr(
            entry, mft_entry_dict["std_info"]["std_info_end"]
        )
        mft_entry_dict["data"] = self.parse_data_attr(entry, mft_entry_dict["file_name"]["file_name_end"])
        return mft_entry_dict

    def istat_mft(self) -> dict:
        pass

    def print_istat_entry(self, istat_entry: dict):
        """Print the istat entry to the screen."""
        data_attr = istat_entry["data"]
        file_name_attr = istat_entry["file_name"]
        std_info_attr = istat_entry["std_info"]
        header_entry = istat_entry["header"]

        result = (
            header_to_str(header_entry)
            + std_info_to_str(std_info_attr)
            + file_name_to_str(file_name_attr)
            + "\nAttributes:\n"
            + attr_to_string(0x10, std_info_attr["std_info_size"])
            + attr_to_string(0x30, file_name_attr["file_name_size"])
        )
        if "init_size" in data_attr:
            result += attr_to_string(0x80, data_attr["size"], data_attr["init_size"])
        else:
            result += attr_to_string(0x80, data_attr["size"])
        if "sector_list" in data_attr:
            result += "\n"
            sector_list = data_attr["sector_list"]
            for x in range(0, len(sector_list), 8):
                result += " ".join([str(x) for x in sector_list[x : x + 8]]) + "\n"
        return result


def main():
    """Argument Parsing"""

    parser = argparse.ArgumentParser(description="Display details of the NTFS MFT entry.")
    parser.add_argument("image", help="Path to an NTFS raw (dd) image")
    parser.add_argument("address", type=int, help="MFT entry number to display stats on")
    args = parser.parse_args()

    with open(args.image, "rb") as fd:
        ntfs = ParseMFT(fd)
        result = ntfs.istat_entry(args.address)
        print(ntfs.print_istat_entry(result))


if __name__ == "__main__":
    main()
