# (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
from ctypes import Structure, c_byte, c_ubyte, c_uint16, c_uint32, c_uint64, sizeof
from typing import Type

import lief


class TargetSectionIsNotFound(RuntimeError):
    pass


class CannotPatchPEHeader(RuntimeError):
    pass


def read_data_rva(obj: lief.PE.Binary, rva_at: int, length: int) -> int:
    sect = obj.section_from_rva(rva_at)
    if sect is None:
        raise TargetSectionIsNotFound
    rva_from_sect_beg = rva_at - sect.virtual_address
    return int.from_bytes(
        bytearray(sect.content[rva_from_sect_beg : rva_from_sect_beg + length]),
        byteorder="little",
    )


def read_word_rva(obj: lief.PE.Binary, rva_at: int) -> int:
    return read_data_rva(obj, rva_at, 2)


def read_dword_rva(obj: lief.PE.Binary, rva_at: int) -> int:
    return read_data_rva(obj, rva_at, 4)


def read_qword_rva(obj: lief.PE.Binary, rva_at: int) -> int:
    return read_data_rva(obj, rva_at, 8)


def patch_pe_rva(obj: lief.PE.Binary, rva_at: int, value: int, size: int) -> None:
    try:
        obj.patch_address(
            rva_at, list(value.to_bytes(size, "little")), lief.Binary.VA_TYPES.RVA
        )
    except lief.not_found:
        patch_pe_header(obj, rva_at, value)


def patch_pe_va(obj: lief.PE.Binary, va_at: int, value: int, size: int) -> None:
    patch_pe_rva(obj, va_at - obj.optional_header.imagebase, value, size)


def patch_header_machine(obj: lief.PE.Binary, value: int) -> None:
    obj.header.machine = lief.PE.MACHINE_TYPES(value)


def patch_entry_point(obj: lief.PE.Binary, value: int) -> None:
    obj.entrypoint = value


class ImageDosHeader(Structure):
    _fields_ = (
        ("e_magic", c_uint16),
        ("e_cblp", c_uint16),
        ("e_cp", c_uint16),
        ("e_crlc", c_uint16),
        ("e_cparhdr", c_uint16),
        ("e_minalloc", c_uint16),
        ("e_maxalloc", c_uint16),
        ("e_ss", c_uint16),
        ("e_sp", c_uint16),
        ("e_csum", c_uint16),
        ("e_ip", c_uint16),
        ("e_cs", c_uint16),
        ("e_lfarlc", c_uint16),
        ("e_ovno", c_uint16),
        ("e_res1", c_uint16 * 4),
        ("e_oemid", c_uint16),
        ("e_oeminfo", c_uint16),
        ("e_res2", c_uint16 * 10),
        ("e_lfanew", c_uint32),
    )


class ImageFileHeader(Structure):
    _fields_ = (
        ("Machine", c_uint16),
        ("NumberOfSections", c_uint16),
        ("TimeDateStamp", c_uint32),
        ("PointerToSymbolTable", c_uint32),
        ("NumberOfSymbols", c_uint32),
        ("SizeOfOptionalHeader", c_uint16),
        ("Characteristics", c_uint16),
    )


class ImageDataDirectory(Structure):
    _fields_ = (("ImageBaseOffset", c_uint32), ("Size", c_uint32))


def make_optional_haeder(bits: int) -> Type[Structure]:
    if bits != 32 and bits != 64:
        raise RuntimeError("bits should be 32 or 64")

    if bits == 32:
        ul_type = c_uint32
    else:
        ul_type = c_uint64

    class ImageOptionalHeader(Structure):
        _fields_ = (
            ("Magic", c_uint16),
            ("MajorLinkerVersion", c_ubyte),
            ("MinorLinkerVersion", c_ubyte),
            ("SizeOfCode", c_uint32),
            ("SizeOfInitializedData", c_uint32),
            ("SizeOfUninitializedData", c_uint32),
            ("AddressOfEntryPoint", c_uint32),
            ("BaseOfCode", c_uint32),
            ("ImageBase", ul_type),
            ("SectionAlignment", c_uint32),
            ("FileAlignment", c_uint32),
            ("MajorOperatingSystemVersion", c_uint16),
            ("MinorOperatingSystemVersion", c_uint16),
            ("MajorImageVersion", c_uint16),
            ("MinorImageVersion", c_uint16),
            ("MajorSubsystemVersion", c_uint16),
            ("MinorSubsystemVersion", c_uint16),
            ("Win32VersionValue", c_uint32),
            ("SizeOfImage", c_uint32),
            ("SizeOfHeaders", c_uint32),
            ("CheckSum", c_uint32),
            ("Subsystem", c_uint16),
            ("DllCharacteristics", c_uint16),
            ("SizeOfStackReserve", ul_type),
            ("SizeOfStackCommit", ul_type),
            ("SizeOfHeapReserve", ul_type),
            ("SizeOfHeapCommit", ul_type),
            ("LoaderFlags", c_uint32),
            ("NumberOfRvaAndSizes", c_uint32),
            ("ImageDataDirectories", ImageDataDirectory * 16),
        )

    return ImageOptionalHeader


def make_image_nt_headers(bits: int) -> Type[Structure]:
    class ImageNtHeaders(Structure):
        _fields_ = (
            ("Signature", c_uint32),
            ("FileHeader", ImageFileHeader),
            ("OptionalHeader", make_optional_haeder(bits)),
        )

    return ImageNtHeaders


class ImageSectionHeader(Structure):
    _fields_ = (
        ("Name", c_byte * 8),
        ("Misc", c_uint32),
        ("VirtualAddress", c_uint32),
        ("SizeOfRawData", c_uint32),
        ("PointerToRawData", c_uint32),
        ("PointerToRelocations", c_uint32),
        ("PointerToLinenumbers", c_uint32),
        ("NumberOfRelocations", c_uint16),
        ("NumberOfLinenumbers", c_uint16),
        ("Characteristics", c_uint32),
    )


def patch_section_header_entry(
    section: lief.PE.Section, offset_from_section: int, value: int
) -> None:
    if offset_from_section == ImageSectionHeader.Name.offset:
        section.name = value.to_bytes(length=8, byteorder="little").decode("utf-8")
    elif offset_from_section == ImageSectionHeader.Misc.offset:
        raise CannotPatchPEHeader("LIEF cannot patch IMAGE_SECTION_HEADER.Misc entry")
    elif offset_from_section == ImageSectionHeader.VirtualAddress.offset:
        section.virtual_address = value
    elif offset_from_section == ImageSectionHeader.SizeOfRawData.offset:
        section.sizeof_raw_data = value
    elif offset_from_section == ImageSectionHeader.PointerToRawData.offset:
        section.pointerto_raw_data = value
    elif offset_from_section == ImageSectionHeader.PointerToRelocations.offset:
        section.pointerto_relocation = value
    elif offset_from_section == ImageSectionHeader.PointerToLinenumbers.offset:
        section.pointerto_line_numbers = value
    elif offset_from_section == ImageSectionHeader.NumberOfRelocations.offset:
        section.numberof_relocations = value
    elif offset_from_section == ImageSectionHeader.NumberOfLinenumbers.offset:
        section.numberof_line_numbers = value
    elif offset_from_section == ImageSectionHeader.Characteristics.offset:
        section.characteristics = value
    else:
        raise CannotPatchPEHeader(
            f"Section Name: {section.name}\nOffset: {hex(offset_from_section)}\nValue: {hex(value)}"
        )


def patch_section_header(
    obj: lief.PE.Binary, offset_from_section_header: int, value: int
) -> None:
    section_header_idx = int(offset_from_section_header / sizeof(ImageSectionHeader))

    patch_section_header_entry(
        obj.sections[section_header_idx],
        offset_from_section_header % sizeof(ImageSectionHeader),
        value,
    )


def patch_dos_header(
    obj: lief.PE.Binary, offset_from_dos_header: int, value: int
) -> None:
    dos_header: lief.PE.DosHeader = obj.dos_header

    if offset_from_dos_header == ImageDosHeader.e_magic.offset:
        dos_header.magic = value
    elif offset_from_dos_header == ImageDosHeader.e_cblp:
        dos_header.used_bytes_in_the_last_page = value
    elif offset_from_dos_header == ImageDosHeader.e_cp:
        dos_header.file_size_in_pages = value
    elif offset_from_dos_header == ImageDosHeader.e_crlc:
        dos_header.numberof_relocation = value
    elif offset_from_dos_header == ImageDosHeader.e_cparhdr:
        dos_header.header_size_in_paragraphs = value
    elif offset_from_dos_header == ImageDosHeader.e_minalloc:
        dos_header.minimum_extra_paragraphs = value
    elif offset_from_dos_header == ImageDosHeader.e_maxalloc:
        dos_header.maximum_extra_paragraphs = value
    elif offset_from_dos_header == ImageDosHeader.e_ss:
        dos_header.initial_relative_ss = value
    elif offset_from_dos_header == ImageDosHeader.e_sp:
        dos_header.initial_sp = value
    elif offset_from_dos_header == ImageDosHeader.e_csum:
        dos_header.checksum = value
    elif offset_from_dos_header == ImageDosHeader.e_ip:
        dos_header.initial_ip = value
    elif offset_from_dos_header == ImageDosHeader.e_cs:
        dos_header.initial_relative_cs = value
    elif offset_from_dos_header == ImageDosHeader.e_lfarlc:
        dos_header.addressof_new_exeheader = value
    elif offset_from_dos_header == ImageDosHeader.e_ovno:
        dos_header.overlay_number = value
    elif offset_from_dos_header == ImageDosHeader.e_oemid:
        dos_header.oem_id = value
    elif offset_from_dos_header == ImageDosHeader.e_oeminfo:
        dos_header.oem_info = value
    elif offset_from_dos_header == ImageDosHeader.e_lfanew:
        dos_header.addressof_new_exeheader = value
    else:
        raise CannotPatchPEHeader(f"Cannot patch dos header")


def is_32bit_image(obj: lief.PE.Binary) -> bool:
    return obj.header.machine in (lief.PE.MACHINE_TYPES.I386,)


def patch_file_header(
    obj: lief.PE.Binary, offset_from_file_header: int, value: int
) -> None:
    if offset_from_file_header == ImageFileHeader.Machine.offset:
        obj.header.machine = lief.PE.MACHINE_TYPES(value)
    elif offset_from_file_header == ImageFileHeader.NumberOfSections.offset:
        obj.header.numberof_sections = value
    elif offset_from_file_header == ImageFileHeader.TimeDateStamp.offset:
        obj.header.time_date_stamps = value
    elif offset_from_file_header == ImageFileHeader.PointerToSymbolTable.offset:
        obj.header.pointerto_symbol_table = value
    elif offset_from_file_header == ImageFileHeader.NumberOfSymbols.offset:
        obj.header.numberof_symbols = value
    elif offset_from_file_header == ImageFileHeader.SizeOfOptionalHeader.offset:
        obj.header.sizeof_optional_header = value
    elif offset_from_file_header == ImageFileHeader.Characteristics.offset:
        obj.header.characteristics = value


def patch_data_directories(
    obj: lief.PE.Binary,
    offset_from_data_directories: int,
    value: int,
) -> None:
    data_dir_idx = int(offset_from_data_directories / sizeof(ImageDataDirectory))
    data_dir_offset = offset_from_data_directories % sizeof(ImageDataDirectory)

    if data_dir_offset == ImageDataDirectory.ImageBaseOffset.offset:
        obj.data_directories[data_dir_idx].rva = value
    elif data_dir_offset == ImageDataDirectory.Size.offset:
        obj.data_directories[data_dir_idx].size = value
    else:
        raise CannotPatchPEHeader(f"Cannot patch Image Data Directory entry")


def patch_optional_header(
    obj: lief.PE.Binary,
    offset_from_optional_header: int,
    value: int,
    optional_header: Type[Structure],
) -> None:
    if offset_from_optional_header == optional_header.Magic.offset:
        obj.optional_header.magic = lief.PE.PE_TYPE(value)
    elif offset_from_optional_header == optional_header.MajorLinkerVersion.offset:
        obj.optional_header.major_linker_version = value
    elif offset_from_optional_header == optional_header.MinorLinkerVersion.offset:
        obj.optional_header.minor_linker_version = value
    elif offset_from_optional_header == optional_header.SizeOfCode.offset:
        obj.optional_header.sizeof_code = value
    elif offset_from_optional_header == optional_header.SizeOfInitializedData.offset:
        obj.optional_header.sizeof_initialized_data = value
    elif offset_from_optional_header == optional_header.SizeOfUninitializedData.offset:
        obj.optional_header.sizeof_uninitialized_data = value
    elif offset_from_optional_header == optional_header.AddressOfEntryPoint.offset:
        obj.optional_header.addressof_entrypoint = value
    elif offset_from_optional_header == optional_header.BaseOfCode.offset:
        obj.optional_header.image_nt_headers = value
    elif offset_from_optional_header == optional_header.ImageBase.offset:
        obj.optional_header.imagebase = value
    elif offset_from_optional_header == optional_header.SectionAlignment.offset:
        obj.optional_header.section_alignment = value
    elif offset_from_optional_header == optional_header.FileAlignment.offset:
        obj.optional_header.file_alignment = value
    elif (
        offset_from_optional_header
        == optional_header.MajorOperatingSystemVersion.offset
    ):
        obj.optional_header.major_operating_system_version = value
    elif (
        offset_from_optional_header
        == optional_header.MinorOperatingSystemVersion.offset
    ):
        obj.optional_header.minor_operating_system_version = value
    elif offset_from_optional_header == optional_header.MajorImageVersion.offset:
        obj.optional_header.major_image_version = value
    elif offset_from_optional_header == optional_header.MinorImageVersion.offset:
        obj.optional_header.minor_image_version = value
    elif offset_from_optional_header == optional_header.MajorSubsystemVersion.offset:
        obj.optional_header.major_subsystem_version = value
    elif offset_from_optional_header == optional_header.MinorSubsystemVersion.offset:
        obj.optional_header.minor_subsystem_version = value
    elif offset_from_optional_header == optional_header.Win32VersionValue.offset:
        obj.optional_header.win32_version_value = value
    elif offset_from_optional_header == optional_header.SizeOfImage.offset:
        obj.optional_header.sizeof_image = value
    elif offset_from_optional_header == optional_header.SizeOfHeaders.offset:
        obj.optional_header.sizeof_headers = value
    elif offset_from_optional_header == optional_header.CheckSum.offset:
        obj.optional_header.CheckSum = value
    elif offset_from_optional_header == optional_header.Subsystem.offset:
        obj.optional_header.subsystem = value
    elif offset_from_optional_header == optional_header.DllCharacteristics.offset:
        obj.optional_header.dll_characteristics = value
    elif offset_from_optional_header == optional_header.SizeOfStackReserve.offset:
        obj.optional_header.sizeof_stack_reserve = value
    elif offset_from_optional_header == optional_header.SizeOfStackCommit.offset:
        obj.optional_header.sizeof_stack_commit = value
    elif offset_from_optional_header == optional_header.SizeOfHeapReserve.offset:
        obj.optional_header.sizeof_heap_reserve = value
    elif offset_from_optional_header == optional_header.SizeOfHeapCommit.offset:
        obj.optional_header.sizeof_heap_commit = value
    elif offset_from_optional_header == optional_header.LoaderFlags.offset:
        obj.optional_header.loader_flags = value
    elif offset_from_optional_header == optional_header.NumberOfRvaAndSizes.offset:
        obj.optional_header.numberof_rva_and_size = value
    elif offset_from_optional_header >= optional_header.ImageDataDirectories.offset:
        patch_data_directories(
            obj,
            offset_from_optional_header - optional_header.ImageDataDirectories.offset,
            value,
        )


def patch_nt_header(
    obj: lief.PE.Binary,
    offset_from_nt_header: int,
    value: int,
    image_nt_headers: Type[Structure],
) -> None:
    if offset_from_nt_header == image_nt_headers.Signature.offset:
        obj.header.signature = value
    elif (
        image_nt_headers.FileHeader.offset
        <= offset_from_nt_header
        < image_nt_headers.OptionalHeader.offset
    ):
        patch_file_header(
            obj, offset_from_nt_header - image_nt_headers.FileHeader.offset, value
        )
    else:
        if is_32bit_image(obj):
            optional_header = make_optional_haeder(32)
        else:
            optional_header = make_optional_haeder(64)

        patch_optional_header(
            obj,
            offset_from_nt_header - image_nt_headers.OptionalHeader.offset,
            value,
            optional_header,
        )


def patch_pe_header(obj: lief.PE.Binary, rva_at: int, value: int) -> None:
    if is_32bit_image(obj):
        image_nt_headers = make_image_nt_headers(32)
    else:
        image_nt_headers = make_image_nt_headers(64)

    image_nt_header_begin = obj.dos_header.addressof_new_exeheader
    image_section_header_begin = image_nt_header_begin + sizeof(image_nt_headers)

    if rva_at < image_nt_header_begin:  # DOS Header
        patch_dos_header(obj, rva_at, value)
    elif image_nt_header_begin <= rva_at < image_section_header_begin:  # NT Header
        patch_nt_header(obj, rva_at - image_nt_header_begin, value, image_nt_headers)
    else:  # Section Header
        patch_section_header(obj, rva_at - image_section_header_begin, value)
