#!/usr/bin/env python3
"""PROJECT: LiberNT ELF to PE converter
LICENSE: GPL-3.0-or-later (https://spdx.org/licenses/GPL-3.0-or-later)
PURPOSE: Convert linked LoongArch64 ELF images to PE32+ images.
COPYRIGHT: Copyright 2026 wuggy <wuggy@billgates.sex>
"""

import argparse
import json
import shlex
import struct
import sys


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
ELF_SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
ELF_SYMBOL = struct.Struct("<IBBHQQ")
ELF_RELA = struct.Struct("<QQq")
ELF_RELR = struct.Struct("<Q")
ELF_DYNAMIC = struct.Struct("<qQ")
PE_COFF_HEADER = struct.Struct("<HHIIIHH")
PE_OPTIONAL_HEADER = struct.Struct("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII")
PE_SECTION_HEADER = struct.Struct("<8sIIIIIIHHI")

EM_LOONGARCH = 258
ET_EXEC = 2
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PF_X = 1
PF_W = 2
PF_R = 4
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_REL = 9
SHT_RELR = 19
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHF_ALLOC = 0x2
SHN_UNDEF = 0
SHN_ABS = 0xFFF1
R_LARCH_NONE = 0
R_LARCH_32 = 1
R_LARCH_64 = 2
R_LARCH_RELATIVE = 3
R_LARCH_JUMP_SLOT = 5
R_LARCH_MARK_LA = 20
R_LARCH_MARK_PCREL = 21
R_LARCH_RELAX = 100
R_LARCH_ABS_HI20 = 67
R_LARCH_ABS_LO12 = 68
R_LARCH_ABS64_LO20 = 69
R_LARCH_ABS64_HI12 = 70
R_LARCH_GOT_PC_HI20 = 75
R_LARCH_GOT_PC_LO12 = 76
R_LARCH_GOT64_PC_LO20 = 77
R_LARCH_GOT64_PC_HI12 = 78
R_LARCH_GOT_HI20 = 79
R_LARCH_GOT_LO12 = 80
R_LARCH_GOT64_LO20 = 81
R_LARCH_GOT64_HI12 = 82
DT_NEEDED = 1
DT_RELRSZ = 35
DT_RELR = 36
DT_RELRENT = 37
R_LARCH_32_PCREL = 99
IMAGE_FILE_MACHINE_LOONGARCH64 = 0x6264
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020
IMAGE_FILE_DLL = 0x2000
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_DIR64 = 10
IMAGE_REL_BASED_LOONGARCH64_MARK_LA = 8
IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
IMAGE_SUBSYSTEM_POSIX_CUI = 7
IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
FILE_ALIGNMENT = 0x200
SECTION_ALIGNMENT = 0x1000
PE_HEADER_OFFSET = 0x80
PE_OPTIONAL_HEADER_SIZE = 240


class ConversionError(Exception):
    pass


def read_string(data, offset):
    if offset >= len(data):
        raise ConversionError("string table offset is outside the ELF file")
    end = data.find(b"\0", offset)
    if end < 0:
        raise ConversionError("unterminated ELF string")
    return data[offset:end].decode("utf-8", errors="strict")


def get_bytes(data, offset, size, what):
    end = offset + size
    if offset < 0 or size < 0 or end > len(data):
        raise ConversionError(f"{what} extends beyond the ELF file")
    return data[offset:end]


def align(value, alignment):
    return (value + alignment - 1) & -alignment


class ElfImage:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as stream:
            self.data = stream.read()
        if len(self.data) < ELF_HEADER.size:
            raise ConversionError("input is shorter than an ELF64 header")
        fields = ELF_HEADER.unpack_from(self.data)
        ident = fields[0]
        if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
            raise ConversionError("input must be a little-endian ELF64 image")
        (
            self.elf_type,
            self.machine,
            version,
            self.entry,
            phoff,
            shoff,
            self.flags,
            ehsize,
            phentsize,
            phnum,
            shentsize,
            shnum,
            shstrndx,
        ) = fields[1:]
        if self.machine != EM_LOONGARCH:
            raise ConversionError(f"ELF machine {self.machine} is not LoongArch64")
        if self.elf_type not in (ET_EXEC, ET_DYN):
            raise ConversionError("input must be a linked ET_EXEC or ET_DYN image")
        if version != 1 or ehsize != ELF_HEADER.size:
            raise ConversionError("unsupported ELF version or header size")
        if phentsize != ELF_PROGRAM_HEADER.size:
            raise ConversionError("unsupported ELF program-header size")
        if shentsize != ELF_SECTION_HEADER.size:
            raise ConversionError("unsupported ELF section-header size")
        if shnum == 0 or shstrndx >= shnum:
            raise ConversionError("ELF section table or string-table index is missing")
        get_bytes(self.data, phoff, phnum * phentsize, "ELF program-header table")
        get_bytes(self.data, shoff, shnum * shentsize, "ELF section-header table")
        self.program_headers = [
            ELF_PROGRAM_HEADER.unpack_from(self.data, phoff + i * phentsize)
            for i in range(phnum)
        ]
        raw_sections = [
            ELF_SECTION_HEADER.unpack_from(self.data, shoff + i * shentsize)
            for i in range(shnum)
        ]
        names_header = raw_sections[shstrndx]
        if names_header[1] != SHT_STRTAB:
            raise ConversionError("ELF section-name table is not a string table")
        names = get_bytes(self.data, names_header[4], names_header[5], "ELF section names")
        self.sections = []
        for index, section in enumerate(raw_sections):
            name = read_string(names, section[0])
            self.sections.append(
                {
                    "index": index,
                    "name": name,
                    "type": section[1],
                    "flags": section[2],
                    "address": section[3],
                    "offset": section[4],
                    "size": section[5],
                    "link": section[6],
                    "info": section[7],
                    "alignment": section[8],
                    "entry_size": section[9],
                }
            )
        self.load_segments = []
        for header in self.program_headers:
            if header[0] != PT_LOAD or header[6] == 0:
                continue
            self.load_segments.append(
                {
                    "offset": header[2],
                    "address": header[3],
                    "file_size": header[5],
                    "memory_size": header[6],
                    "alignment": header[7],
                    "flags": header[1],
                    "data": bytearray(
                        get_bytes(self.data, header[2], header[5], "ELF load segment")
                    ),
                    "rva": 0,
                    "raw_offset": 0,
                }
            )
        if not self.load_segments:
            raise ConversionError("ELF image has no loadable segments")
        if any(segment["file_size"] > segment["memory_size"] for segment in self.load_segments):
            raise ConversionError("ELF load segment has filesz greater than memsz")
        if any(header[0] == PT_INTERP for header in self.program_headers):
            raise ConversionError("ELF interpreter is unsupported; link a self-contained image")
        self.base_address = min(segment["address"] for segment in self.load_segments)
        self.image_end = max(
            segment["address"] + segment["memory_size"] for segment in self.load_segments
        )
        if self.base_address % SECTION_ALIGNMENT:
            raise ConversionError("lowest ELF load segment is not section-aligned")
        ordered_segments = sorted(self.load_segments, key=lambda segment: segment["address"])
        for previous, current in zip(ordered_segments, ordered_segments[1:]):
            if previous["address"] + previous["memory_size"] > current["address"]:
                raise ConversionError("overlapping ELF load segments are unsupported")

    def virtual_to_segment(self, address, size):
        for segment in self.load_segments:
            start = segment["address"]
            end = start + segment["memory_size"]
            if start <= address and address + size <= end:
                offset = address - start
                required = offset + size
                if required > len(segment["data"]):
                    segment["data"].extend(bytes(required - len(segment["data"])))
                return segment, offset
        raise ConversionError(f"address 0x{address:x} is outside loadable ELF segments")

    def write_virtual(self, address, data):
        segment, offset = self.virtual_to_segment(address, len(data))
        segment["data"][offset : offset + len(data)] = data

    def read_virtual(self, address, size):
        segment, offset = self.virtual_to_segment(address, size)
        return bytes(segment["data"][offset : offset + size])


def symbol_tables(image):
    tables = {}
    for section in image.sections:
        if section["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if section["link"] >= len(image.sections):
            raise ConversionError(f"invalid string-table link in {section['name']}")
        strings_section = image.sections[section["link"]]
        if strings_section["type"] != SHT_STRTAB:
            raise ConversionError(f"invalid string-table link in {section['name']}")
        strings = get_bytes(
            image.data,
            strings_section["offset"],
            strings_section["size"],
            "ELF symbol strings",
        )
        entry_size = section["entry_size"] or ELF_SYMBOL.size
        if entry_size != ELF_SYMBOL.size or section["size"] % entry_size:
            raise ConversionError(f"unsupported symbol table format in {section['name']}")
        symbols = []
        raw = get_bytes(image.data, section["offset"], section["size"], section["name"])
        for offset in range(0, len(raw), entry_size):
            name, info, other, shndx, value, size = ELF_SYMBOL.unpack_from(raw, offset)
            symbols.append(
                {
                    "name": read_string(strings, name),
                    "binding": info >> 4,
                    "type": info & 0xF,
                    "other": other,
                    "section": shndx,
                    "value": value,
                    "size": size,
                }
            )
        tables[section["index"]] = symbols
    return tables


def relocation_entries(image, tables):
    entries = []
    for section in image.sections:
        if section["type"] == SHT_REL:
            if section["info"] >= len(image.sections):
                raise ConversionError(f"invalid target-section link in {section['name']}")
            if section["info"] == 0 or image.sections[section["info"]]["flags"] & SHF_ALLOC:
                raise ConversionError(f"SHT_REL relocations are unsupported in {section['name']}")
            continue
        if section["type"] != SHT_RELA:
            continue
        if section["info"] >= len(image.sections):
            raise ConversionError(f"invalid target-section link in {section['name']}")
        if section["info"] < len(image.sections) and section["info"] != 0:
            if not image.sections[section["info"]]["flags"] & SHF_ALLOC:
                continue
        entry_size = section["entry_size"] or ELF_RELA.size
        if entry_size != ELF_RELA.size or section["size"] % entry_size:
            raise ConversionError(f"unsupported relocation table format in {section['name']}")
        if section["link"] not in tables:
            raise ConversionError(f"invalid symbol-table link in {section['name']}")
        symbols = tables[section["link"]]
        raw = get_bytes(image.data, section["offset"], section["size"], section["name"])
        for offset in range(0, len(raw), entry_size):
            address, info, addend = ELF_RELA.unpack_from(raw, offset)
            reloc_type = info & 0xFFFFFFFF
            symbol_index = info >> 32
            symbol = symbols[symbol_index] if symbol_index < len(symbols) else None
            if symbol_index and symbol is None:
                raise ConversionError(f"invalid symbol index in {section['name']}")
            entries.append((section["name"], address, reloc_type, symbol, addend))
    return entries


def apply_relr_relocations(image, base_address):
    relocations = {}
    image_delta = base_address + image.rva_bias - image.base_address
    for section in image.sections:
        if section["type"] != SHT_RELR:
            continue
        entry_size = section["entry_size"] or ELF_RELR.size
        if entry_size != ELF_RELR.size or section["size"] % entry_size:
            raise ConversionError(f"unsupported RELR table format in {section['name']}")
        raw = get_bytes(image.data, section["offset"], section["size"], section["name"])
        next_address = None

        def relocate(address):
            if address & 7:
                raise ConversionError(f"unaligned RELR relocation in {section['name']}")
            value = struct.unpack("<Q", image.read_virtual(address, 8))[0]
            image.write_virtual(address, struct.pack("<Q", value + image_delta))
            relocations[address - image.base_address + image.rva_bias] = IMAGE_REL_BASED_DIR64

        for offset in range(0, len(raw), entry_size):
            entry = ELF_RELR.unpack_from(raw, offset)[0]
            if entry & 1 == 0:
                relocate(entry)
                next_address = entry + ELF_RELR.size
                continue
            if next_address is None:
                raise ConversionError(f"RELR bitmap precedes an address in {section['name']}")
            bitmap = entry >> 1
            for bit in range(63):
                if bitmap & (1 << bit):
                    relocate(next_address + bit * ELF_RELR.size)
            next_address += 63 * ELF_RELR.size
    return relocations


def preferred_address(image, requested):
    if requested is not None:
        if requested & 0xFFFF:
            raise ConversionError("PE image base must be 64 KiB aligned")
        image.rva_bias = SECTION_ALIGNMENT
        return requested
    if image.elf_type == ET_EXEC:
        candidate = align(image.base_address - SECTION_ALIGNMENT, 0x10000) - 0x10000
        if candidate > 0 and candidate < image.base_address:
            image.rva_bias = image.base_address - candidate
            return candidate
    image.rva_bias = SECTION_ALIGNMENT
    return 0x140000000


def apply_relocations(
    image, tables, base_address, import_relocations, iat_rvas, got_accesses
):
    relocations = {}
    image_delta = base_address + image.rva_bias - image.base_address
    entries = relocation_entries(image, tables)
    entry_by_site = {
        (address, reloc_type): (symbol, addend)
        for _, address, reloc_type, symbol, addend in entries
    }
    processed_absolute_sequences = set()
    got_access_by_address = {
        address: (reloc_type, import_key)
        for _, address, reloc_type, import_key in got_accesses
    }
    for section_name, address, reloc_type, symbol, addend in entries:
        if reloc_type in (R_LARCH_NONE, R_LARCH_MARK_PCREL, R_LARCH_RELAX):
            continue
        sequence_start_type = None
        if R_LARCH_ABS_HI20 <= reloc_type <= R_LARCH_ABS64_HI12:
            sequence_start_type = R_LARCH_ABS_HI20
        elif R_LARCH_GOT_HI20 <= reloc_type <= R_LARCH_GOT64_HI12:
            sequence_start_type = R_LARCH_GOT_HI20
        if sequence_start_type is not None:
            sequence_start = address - (reloc_type - sequence_start_type) * 4
            if sequence_start in processed_absolute_sequences:
                continue
            if sequence_start & 3:
                raise ConversionError(f"unaligned LoongArch absolute-address sequence in {section_name}")
            if sequence_start_type == R_LARCH_ABS_HI20:
                sequence_types = list(range(R_LARCH_ABS_HI20, R_LARCH_ABS64_HI12 + 1))
            else:
                sequence_types = [R_LARCH_GOT_HI20, R_LARCH_GOT_LO12]
                has_upper_low = (sequence_start + 8, R_LARCH_GOT64_LO20) in entry_by_site
                has_upper_high = (sequence_start + 12, R_LARCH_GOT64_HI12) in entry_by_site
                if has_upper_low != has_upper_high:
                    raise ConversionError(
                        f"incomplete LoongArch 64-bit GOT sequence in {section_name}"
                    )
                if has_upper_low:
                    sequence_types.extend((R_LARCH_GOT64_LO20, R_LARCH_GOT64_HI12))
            sequence_addresses = [sequence_start + index * 4 for index in range(len(sequence_types))]
            sequence = []
            for sequence_address, sequence_relocation in zip(sequence_addresses, sequence_types):
                if (sequence_address, sequence_relocation) not in entry_by_site:
                    raise ConversionError(
                        f"incomplete LoongArch absolute-address sequence in {section_name}"
                    )
                sequence.append(entry_by_site[(sequence_address, sequence_relocation)])
            first_symbol, first_addend = sequence[0]
            if sequence_start_type == R_LARCH_ABS_HI20:
                symbol_key = (
                    (first_symbol["name"], first_symbol["value"], first_symbol["section"])
                    if first_symbol is not None
                    else None
                )
                if any(
                    (
                        (item[0]["name"], item[0]["value"], item[0]["section"])
                        if item[0] is not None
                        else None
                    )
                    != symbol_key
                    or item[1] != first_addend
                    for item in sequence[1:]
                ):
                    raise ConversionError(
                        f"inconsistent LoongArch absolute-address sequence in {section_name}"
                    )
                if first_symbol is not None and first_symbol["section"] == SHN_UNDEF:
                    raise ConversionError(
                        f"unresolved absolute LoongArch import {first_symbol['name']}"
                    )
                value = first_addend if first_symbol is None else first_symbol["value"] + first_addend
                if first_symbol is None or first_symbol["section"] != SHN_ABS:
                    if image.base_address <= value <= image.image_end:
                        value += image_delta
            else:
                words = []
                for sequence_address in sequence_addresses:
                    segment, offset = image.virtual_to_segment(sequence_address, 4)
                    words.append(struct.unpack_from("<I", segment["data"], offset)[0])
                value = (
                    ((words[0] & 0x1FFFFE0) << 7)
                    | ((words[1] & 0x3FFC00) >> 10)
                )
                if len(words) == 4:
                    value |= ((words[2] & 0x1FFFFE0) << 27)
                    value |= (words[3] & 0x3FFC00) << 42
                else:
                    high = (words[0] & 0x1FFFFE0) >> 5
                    if high & 0x80000:
                        value |= 0xFFFFFFFF00000000
                import_access = next(
                    (
                        got_access_by_address[sequence_address]
                        for sequence_address in sequence_addresses
                        if sequence_address in got_access_by_address
                    ),
                    None,
                )
                if first_symbol is not None and first_symbol["section"] == SHN_UNDEF:
                    if import_access is None:
                        raise ConversionError(
                            f"unresolved absolute LoongArch import {first_symbol['name']}"
                        )
                    value = base_address + iat_rvas[import_access[1]]
                elif image.base_address <= value <= image.image_end:
                    value += image_delta
                if len(words) == 2:
                    low32 = value & 0xFFFFFFFF
                    sign_extended = low32 | (0xFFFFFFFF00000000 if low32 & 0x80000000 else 0)
                    if value != sign_extended:
                        raise ConversionError(
                            f"32-bit absolute GOT address in {section_name} cannot represent 0x{value:x}"
                        )
                    image.requires_fixed_base = True
            for index, sequence_address in enumerate(sequence_addresses):
                segment, offset = image.virtual_to_segment(sequence_address, 4)
                instruction = struct.unpack_from("<I", segment["data"], offset)[0]
                if index in (0, 2):
                    immediate = (value >> (12 if index == 0 else 32)) & 0xFFFFF
                    instruction = (instruction & ~0x1FFFFE0) | (immediate << 5)
                else:
                    immediate = (value >> (0 if index == 1 else 52)) & 0xFFF
                    instruction = (instruction & ~0x3FFC00) | (immediate << 10)
                struct.pack_into("<I", segment["data"], offset, instruction)
            if len(sequence_addresses) == 4:
                rva = sequence_start - image.base_address + image.rva_bias
                relocations[rva] = IMAGE_REL_BASED_LOONGARCH64_MARK_LA
            processed_absolute_sequences.add(sequence_start)
            continue
        if reloc_type in range(R_LARCH_GOT_PC_HI20, R_LARCH_GOT64_HI12 + 1):
            if symbol is not None and symbol["section"] == SHN_UNDEF:
                access = got_access_by_address.get(address)
                if access is None:
                    raise ConversionError(f"unresolved LoongArch GOT import in {section_name}")
                _, import_key = access
                target = base_address + iat_rvas[import_key]
                pc = base_address + address - image.base_address + image.rva_bias
                if reloc_type == R_LARCH_GOT_PC_HI20:
                    delta = (target & ~0xFFF) - (pc & ~0xFFF)
                    high = delta >> 12
                    if high < -(1 << 19) or high >= (1 << 19):
                        raise ConversionError(
                            f"PE import IAT is out of range for LoongArch GOT access in {section_name}"
                        )
                    immediate = high & 0xFFFFF
                    mask = 0x1FFFFE0
                    shift = 5
                elif reloc_type == R_LARCH_GOT_PC_LO12:
                    immediate = target & 0xFFF
                    mask = 0x3FFC00
                    shift = 10
                elif reloc_type == R_LARCH_GOT64_PC_LO20:
                    delta = (target - (pc & ~0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
                    immediate = (delta >> 32) & 0xFFFFF
                    mask = 0x1FFFFE0
                    shift = 5
                else:
                    delta = (target - (pc & ~0xFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF
                    immediate = (delta >> 52) & 0xFFF
                    mask = 0x3FFC00
                    shift = 10
                segment, offset = image.virtual_to_segment(address, 4)
                instruction = struct.unpack_from("<I", segment["data"], offset)[0]
                instruction = (instruction & ~mask) | (immediate << shift)
                struct.pack_into("<I", segment["data"], offset, instruction)
                continue
            if reloc_type >= R_LARCH_GOT_HI20 and image_delta:
                raise ConversionError(
                    f"absolute LoongArch GOT relocation {reloc_type} in {section_name} "
                    "cannot be rebased safely"
                )
            continue
        if reloc_type == R_LARCH_MARK_LA:
            if address & 3:
                raise ConversionError(f"unaligned R_LARCH_MARK_LA in {section_name}")
            segment, offset = image.virtual_to_segment(address, 16)
            words = list(struct.unpack_from("<IIII", segment["data"], offset))
            value = (
                ((words[0] & 0x1FFFFE0) << 7)
                | ((words[1] & 0x3FFC00) >> 10)
                | ((words[2] & 0x1FFFFE0) << 27)
                | ((words[3] & 0x3FFC00) << 42)
            )
            if symbol is not None and symbol["section"] == SHN_UNDEF:
                import_key = import_relocations.get(address)
                if import_key is None:
                    raise ConversionError(f"unresolved ELF import {symbol['name']}")
                value = base_address + iat_rvas[import_key]
            elif image.base_address <= value <= image.image_end:
                value += image_delta
            words[0] = (words[0] & ~0x1FFFFE0) | (((value >> 12) & 0xFFFFF) << 5)
            words[1] = (words[1] & ~0x3FFC00) | ((value & 0xFFF) << 10)
            words[2] = (words[2] & ~0x1FFFFE0) | (((value >> 32) & 0xFFFFF) << 5)
            words[3] = (words[3] & ~0x3FFC00) | (((value >> 52) & 0xFFF) << 10)
            struct.pack_into("<IIII", segment["data"], offset, *words)
            rva = address - image.base_address + image.rva_bias
            relocations[rva] = IMAGE_REL_BASED_LOONGARCH64_MARK_LA
            continue
        if reloc_type == R_LARCH_RELATIVE:
            if symbol is not None and symbol["section"] != SHN_UNDEF:
                raise ConversionError(
                    f"R_LARCH_RELATIVE unexpectedly references a symbol in {section_name}"
                )
            image.virtual_to_segment(address, 8)
            relative = addend - image.base_address + image.rva_bias
            image.write_virtual(address, struct.pack("<Q", base_address + relative))
            relocations[address - image.base_address + image.rva_bias] = IMAGE_REL_BASED_DIR64
            continue
        if reloc_type == R_LARCH_JUMP_SLOT:
            if symbol is None:
                raise ConversionError(f"invalid R_LARCH_JUMP_SLOT in {section_name}")
            if symbol["section"] == SHN_UNDEF:
                continue
            if addend:
                raise ConversionError(f"nonzero R_LARCH_JUMP_SLOT addend in {section_name}")
            value = symbol["value"]
            if image.base_address <= value <= image.image_end:
                value += image_delta
            image.write_virtual(address, struct.pack("<Q", value))
            relocations[address - image.base_address + image.rva_bias] = IMAGE_REL_BASED_DIR64
            continue
        if reloc_type in (R_LARCH_32, R_LARCH_64):
            width = 4 if reloc_type == R_LARCH_32 else 8
            if symbol is not None and symbol["section"] == SHN_UNDEF:
                if address not in import_relocations:
                    raise ConversionError(f"unresolved ELF import {symbol['name'] or '<unnamed>'}")
                continue
            else:
                value = addend if symbol is None else symbol["value"] + addend
            if symbol is not None and symbol["section"] == SHN_ABS:
                value += 0
            elif image.base_address <= value <= image.image_end:
                value += image_delta
            if image.elf_type == ET_DYN or image_delta:
                image.write_virtual(address, struct.pack("<I" if width == 4 else "<Q", value))
            relocations[address - image.base_address + image.rva_bias] = (
                IMAGE_REL_BASED_HIGHLOW if width == 4 else IMAGE_REL_BASED_DIR64
            )
            continue
        if reloc_type in (57, 58, 64, 65, 66, 71, 72, 73, 74, R_LARCH_32_PCREL):
            continue
        if 22 <= reloc_type <= 56:
            if image_delta:
                raise ConversionError(
                    f"LoongArch linker-expression relocation {reloc_type} in {section_name} "
                    "cannot be rebased safely"
                )
            continue
        if 4 <= reloc_type <= 12:
            raise ConversionError(
                f"LoongArch runtime relocation {reloc_type} in {section_name} is not supported"
            )
        raise ConversionError(
            f"LoongArch relocation {reloc_type} in {section_name} is not supported"
        )
    relr_relocations = apply_relr_relocations(image, base_address)
    if set(relocations) & set(relr_relocations):
        raise ConversionError("overlapping RELA and RELR relocation targets")
    relocations.update(relr_relocations)
    return relocations


def check_dynamic_dependencies(image):
    dependencies = []
    dynamic_sections = 0
    dynamic_tags = {}
    for section in image.sections:
        if section["type"] != SHT_DYNAMIC:
            continue
        dynamic_sections += 1
        if section["link"] >= len(image.sections):
            raise ConversionError(f"invalid dynamic string-table link in {section['name']}")
        raw = get_bytes(image.data, section["offset"], section["size"], section["name"])
        entry_size = section["entry_size"] or ELF_DYNAMIC.size
        if entry_size != ELF_DYNAMIC.size or len(raw) % entry_size:
            raise ConversionError(f"unsupported dynamic table format in {section['name']}")
        strings_section = image.sections[section["link"]]
        if strings_section["type"] != SHT_STRTAB:
            raise ConversionError(f"invalid dynamic string-table link in {section['name']}")
        strings = get_bytes(
            image.data,
            strings_section["offset"],
            strings_section["size"],
            "ELF dynamic strings",
        )
        for offset in range(0, len(raw), entry_size):
            tag, value = ELF_DYNAMIC.unpack_from(raw, offset)
            dynamic_tags[tag] = value
            if tag == DT_NEEDED:
                dependency = read_string(strings, value)
                dependencies.append(dependency)
            if tag == 0:
                break
    if any(header[0] == PT_DYNAMIC for header in image.program_headers) and not dynamic_sections:
        raise ConversionError("PT_DYNAMIC has no section-header view")
    relr_sections = [section for section in image.sections if section["type"] == SHT_RELR]
    if any(tag in dynamic_tags for tag in (DT_RELR, DT_RELRSZ, DT_RELRENT)) and not relr_sections:
        raise ConversionError("dynamic tags advertise RELR but no SHT_RELR section is present")
    if relr_sections:
        if DT_RELRENT in dynamic_tags and dynamic_tags[DT_RELRENT] != ELF_RELR.size:
            raise ConversionError("DT_RELRENT does not match the ELF64 RELR entry size")
        if DT_RELRSZ in dynamic_tags and dynamic_tags[DT_RELRSZ] != sum(
            section["size"] for section in relr_sections
        ):
            raise ConversionError("DT_RELRSZ does not match the SHT_RELR section sizes")
    return dependencies


def collect_imports(image, tables, dependencies, import_map):
    imports = {}
    import_relocations = {}
    got_accesses = []
    entries = relocation_entries(image, tables)

    def record_import(section_name, address, symbol):
        name = symbol["name"]
        if not name:
            raise ConversionError(f"unnamed undefined symbol in {section_name}")
        dll_name = import_map.get(name)
        if dll_name is None:
            if len(dependencies) != 1:
                raise ConversionError(
                    f"cannot determine DLL for import {name}; provide --import-map"
                )
            dll_name = dependencies[0]
        if not dll_name:
            raise ConversionError(f"import map assigns an empty DLL name to {name}")
        imports.setdefault(dll_name, set()).add(name)
        return dll_name, name

    dynamic_import_names = set()
    for section_name, address, reloc_type, symbol, addend in entries:
        if reloc_type not in (R_LARCH_32, R_LARCH_64, R_LARCH_JUMP_SLOT):
            continue
        if symbol is None or symbol["section"] != SHN_UNDEF:
            continue
        if reloc_type == R_LARCH_32:
            raise ConversionError(
                f"32-bit ELF import {symbol['name']} cannot target a PE32+ IAT entry"
            )
        import_key = record_import(section_name, address, symbol)
        import_relocations[address] = import_key
        dynamic_import_names.add(symbol["name"])

    for section_name, address, reloc_type, symbol, addend in entries:
        if reloc_type not in range(R_LARCH_GOT_PC_HI20, R_LARCH_GOT64_HI12 + 1):
            continue
        if symbol is None or symbol["section"] != SHN_UNDEF:
            continue
        import_key = record_import(section_name, address, symbol)
        got_accesses.append((section_name, address, reloc_type, import_key))

    converted_names = {import_key[1] for _, _, _, import_key in got_accesses}
    missing = sorted(dynamic_import_names - converted_names)
    if missing:
        raise ConversionError(
            f"imports lack retained LoongArch GOT relocations: {', '.join(missing)}"
        )
    return imports, import_relocations, got_accesses


def build_import_section(imports, rva):
    if not imports:
        return b"", {}, 0
    libraries = sorted(imports)
    descriptor_size = (len(libraries) + 1) * 20
    data = bytearray(descriptor_size)
    cursor = align(descriptor_size, 8)
    iat_rvas = {}
    descriptors = []
    for library in libraries:
        names = sorted(imports[library])
        thunk_count = len(names) + 1
        lookup_offset = cursor
        cursor += thunk_count * 8
        iat_offset = cursor
        cursor += thunk_count * 8
        descriptors.append((library, names, lookup_offset, iat_offset))
        for index, name in enumerate(names):
            iat_rvas[(library, name)] = rva + iat_offset + index * 8
    cursor = align(cursor, 2)
    name_offsets = {}
    for library, names, _, _ in descriptors:
        for name in names:
            name_offsets[(library, name)] = cursor
            cursor += 2 + len(name.encode("ascii")) + 1
            cursor = align(cursor, 2)
    library_offsets = {}
    for library in libraries:
        library_offsets[library] = cursor
        cursor += len(library.encode("ascii")) + 1
    data.extend(bytes(cursor - len(data)))
    for index, (library, names, lookup_offset, iat_offset) in enumerate(descriptors):
        for name_index, name in enumerate(names):
            name_rva = rva + name_offsets[(library, name)]
            struct.pack_into("<Q", data, lookup_offset + name_index * 8, name_rva)
            struct.pack_into("<Q", data, iat_offset + name_index * 8, name_rva)
            struct.pack_into("<H", data, name_offsets[(library, name)], 0)
            encoded_name = name.encode("ascii") + b"\0"
            start = name_offsets[(library, name)] + 2
            data[start : start + len(encoded_name)] = encoded_name
        library_bytes = library.encode("ascii") + b"\0"
        library_offset = library_offsets[library]
        data[library_offset : library_offset + len(library_bytes)] = library_bytes
        struct.pack_into(
            "<IIIII",
            data,
            index * 20,
            rva + lookup_offset,
            0,
            0,
            rva + library_offset,
            rva + iat_offset,
        )
    return bytes(data), iat_rvas, descriptor_size


def read_definition(path):
    module_name = None
    exports = []
    in_exports = False
    with open(path, "r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            line = line.split(";", 1)[0].strip()
            if not line:
                continue
            fields = shlex.split(line)
            directive = fields[0].upper()
            if directive == "NAME" or directive == "LIBRARY":
                if len(fields) != 2:
                    raise ConversionError(f"invalid module name at {path}:{line_number}")
                module_name = fields[1]
                continue
            if directive == "EXPORTS":
                in_exports = True
                continue
            if not in_exports:
                continue
            if len(fields) > 1 and fields[1] == "=" and len(fields) > 2:
                fields[0] += "=" + fields[2]
                del fields[1:3]
            public_name, separator, target = fields[0].partition("=")
            ordinal = None
            noname = False
            for field in fields[1:]:
                if field.startswith("@") and field[1:].isdigit():
                    ordinal = int(field[1:])
                elif field.upper() == "NONAME":
                    noname = True
            if ordinal is None:
                raise ConversionError(f"export has no ordinal at {path}:{line_number}")
            if not public_name:
                raise ConversionError(f"export has no name at {path}:{line_number}")
            exports.append(
                {
                    "name": public_name,
                    "target": target if separator else public_name,
                    "forwarder": bool(separator and "." in target),
                    "ordinal": ordinal,
                    "noname": noname,
                }
            )
    if not module_name:
        raise ConversionError("definition file must contain NAME or LIBRARY")
    return module_name, exports


def build_export_section(image, tables, exports, module_name, rva):
    if not exports:
        return b"", 0
    ordinals = [entry["ordinal"] for entry in exports]
    if (
        len(set(ordinals)) != len(ordinals)
        or min(ordinals) < 0
        or max(ordinals) > 0xFFFF
    ):
        raise ConversionError("definition file contains duplicate or invalid export ordinals")
    names = [entry["name"] for entry in exports if not entry["noname"]]
    if len(set(names)) != len(names):
        raise ConversionError("definition file contains duplicate export names")
    ordinal_base = min(ordinals)
    function_count = max(ordinals) - ordinal_base + 1
    if function_count > 0x10000:
        raise ConversionError("definition file exceeds the PE export ordinal range")
    name_entries = sorted(
        (entry["name"], entry["ordinal"] - ordinal_base)
        for entry in exports
        if not entry["noname"]
    )
    functions_offset = 40
    names_offset = functions_offset + function_count * 4
    ordinals_offset = names_offset + len(name_entries) * 4
    cursor = align(ordinals_offset + len(name_entries) * 2, 4)
    module_offset = cursor
    cursor += len(module_name.encode("ascii")) + 1
    name_offsets = {}
    for name, _ in name_entries:
        name_offsets[name] = cursor
        cursor += len(name.encode("ascii")) + 1
    forwarder_offsets = {}
    for entry in exports:
        if entry["forwarder"]:
            forwarder_offsets[entry["ordinal"]] = cursor
            cursor += len(entry["target"].encode("ascii")) + 1
    data = bytearray(cursor)
    eat = [0] * function_count
    for entry in exports:
        ordinal_index = entry["ordinal"] - ordinal_base
        if entry["forwarder"]:
            eat[ordinal_index] = rva + forwarder_offsets[entry["ordinal"]]
            encoded = entry["target"].encode("ascii") + b"\0"
            start = forwarder_offsets[entry["ordinal"]]
            data[start : start + len(encoded)] = encoded
            continue
        target = entry["target"]
        symbol = next(
            (
                symbol
                for table in tables.values()
                for symbol in table
                if symbol["name"] == target and symbol["section"] != SHN_UNDEF
            ),
            None,
        )
        if symbol is None:
            raise ConversionError(f"export target {target} is not a defined ELF symbol")
        if not image.base_address <= symbol["value"] < image.image_end:
            raise ConversionError(f"export target {target} is outside loadable ELF segments")
        eat[ordinal_index] = symbol["value"] - image.base_address + image.rva_bias
    for index, function_rva in enumerate(eat):
        struct.pack_into("<I", data, functions_offset + index * 4, function_rva)
    for index, (name, ordinal_index) in enumerate(name_entries):
        struct.pack_into("<I", data, names_offset + index * 4, rva + name_offsets[name])
        struct.pack_into("<H", data, ordinals_offset + index * 2, ordinal_index)
        encoded = name.encode("ascii") + b"\0"
        start = name_offsets[name]
        data[start : start + len(encoded)] = encoded
    module_bytes = module_name.encode("ascii") + b"\0"
    data[module_offset : module_offset + len(module_bytes)] = module_bytes
    struct.pack_into(
        "<IIHHIIIIIII",
        data,
        0,
        0,
        0,
        0,
        0,
        rva + module_offset,
        ordinal_base,
        function_count,
        len(name_entries),
        rva + functions_offset,
        rva + names_offset,
        rva + ordinals_offset,
    )
    return bytes(data), len(data)


def build_relocation_section(relocations):
    if not relocations:
        return b""
    pages = {}
    for rva, reloc_type in sorted(relocations.items()):
        page = rva & ~0xFFF
        pages.setdefault(page, []).append((reloc_type << 12) | (rva & 0xFFF))
    output = bytearray()
    for page, entries in sorted(pages.items()):
        if len(entries) & 1:
            entries.append(IMAGE_REL_BASED_ABSOLUTE << 12)
        block_size = 8 + len(entries) * 2
        output.extend(struct.pack("<II", page, block_size))
        output.extend(struct.pack("<" + "H" * len(entries), *entries))
    return bytes(output)


def section_characteristics(segment):
    flags = segment["flags"]
    characteristics = 0
    if flags & PF_X:
        characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE
    elif segment["memory_size"] > len(segment["data"]) and len(segment["data"]) == 0:
        characteristics |= IMAGE_SCN_CNT_UNINITIALIZED_DATA
    else:
        characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA
    if flags & PF_R:
        characteristics |= IMAGE_SCN_MEM_READ
    if flags & PF_W:
        characteristics |= IMAGE_SCN_MEM_WRITE
    return characteristics


def section_name(segment, index):
    flags = segment["flags"]
    if flags & PF_X:
        return b".text"
    if flags & PF_W:
        return b".data" if segment["file_size"] else b".bss"
    return b".rdata" if index == 0 else b".pdata"


def build_pe(
    image,
    base_address,
    subsystem,
    as_dll,
    relocations,
    import_data,
    import_rva,
    import_size,
    export_data,
    export_rva,
):
    load_segments = sorted(image.load_segments, key=lambda segment: segment["address"])
    sections = []
    for index, segment in enumerate(load_segments):
        segment["rva"] = segment["address"] - image.base_address + image.rva_bias
        if segment["rva"] < SECTION_ALIGNMENT:
            raise ConversionError(
                "lowest ELF segment overlaps PE headers; link the ELF image above RVA 0"
            )
        if segment["rva"] % SECTION_ALIGNMENT:
            raise ConversionError("ELF load segment is not aligned to PE section alignment")
        sections.append(
            {
                "name": section_name(segment, index),
                "rva": segment["rva"],
                "virtual_size": segment["memory_size"],
                "data": segment["data"],
                "characteristics": section_characteristics(segment),
                "raw_offset": 0,
            }
        )
    if import_data:
        sections.append(
            {
                "name": b".idata",
                "rva": import_rva,
                "virtual_size": len(import_data),
                "data": bytearray(import_data),
                "characteristics": IMAGE_SCN_CNT_INITIALIZED_DATA
                | IMAGE_SCN_MEM_READ
                | IMAGE_SCN_MEM_WRITE,
                "raw_offset": 0,
            }
        )
    if export_data:
        sections.append(
            {
                "name": b".edata",
                "rva": export_rva,
                "virtual_size": len(export_data),
                "data": bytearray(export_data),
                "characteristics": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                "raw_offset": 0,
            }
        )
    reloc_data = (
        b""
        if getattr(image, "requires_fixed_base", False)
        else build_relocation_section(relocations)
    )
    if reloc_data:
        reloc_rva = align(
            max(section["rva"] + section["virtual_size"] for section in sections),
            SECTION_ALIGNMENT,
        )
        sections.append(
            {
                "name": b".reloc",
                "rva": reloc_rva,
                "virtual_size": len(reloc_data),
                "data": bytearray(reloc_data),
                "characteristics": IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
                "raw_offset": 0,
            }
        )
    if len(sections) > 96:
        raise ConversionError("PE images cannot contain more than 96 sections")
    headers_size = align(
        PE_HEADER_OFFSET
        + 4
        + PE_COFF_HEADER.size
        + PE_OPTIONAL_HEADER_SIZE
        + len(sections) * PE_SECTION_HEADER.size,
        FILE_ALIGNMENT,
    )
    raw_offset = headers_size
    for section in sections:
        data = bytes(section["data"])
        if data:
            section["raw_offset"] = raw_offset
            section["raw_size"] = align(len(data), FILE_ALIGNMENT)
            raw_offset += section["raw_size"]
        else:
            section["raw_offset"] = 0
            section["raw_size"] = 0
    image_size = align(
        max(section["rva"] + section["virtual_size"] for section in sections),
        SECTION_ALIGNMENT,
    )
    if image_size > 0xFFFFFFFF:
        raise ConversionError("PE image exceeds the 32-bit SizeOfImage limit")
    entry_rva = image.entry - image.base_address + image.rva_bias if image.entry else 0
    if entry_rva and not any(
        segment["rva"] <= entry_rva < segment["rva"] + segment["memory_size"]
        and segment["flags"] & PF_X
        for segment in load_segments
    ):
        raise ConversionError("ELF entry point is outside executable load segments")
    if not as_dll and not entry_rva:
        raise ConversionError("executable ELF image has no entry point")
    size_code = sum(
        section["raw_size"]
        for section in sections
        if section["characteristics"] & IMAGE_SCN_CNT_CODE
    )
    size_initialized = sum(
        section["raw_size"]
        for section in sections
        if section["characteristics"] & IMAGE_SCN_CNT_INITIALIZED_DATA
    )
    size_uninitialized = sum(
        section["virtual_size"]
        for section in sections
        if section["characteristics"] & IMAGE_SCN_CNT_UNINITIALIZED_DATA
    )
    optional = bytearray(
        PE_OPTIONAL_HEADER.pack(
            0x20B,
            1,
            0,
            size_code,
            size_initialized,
            size_uninitialized,
            entry_rva,
            next(
                (
                    section["rva"]
                    for section in sections
                    if section["characteristics"] & IMAGE_SCN_CNT_CODE
                ),
                0,
            ),
            base_address,
            SECTION_ALIGNMENT,
            FILE_ALIGNMENT,
            6,
            0,
            1,
            0,
            6,
            0,
            0,
            image_size,
            headers_size,
            0,
            subsystem,
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            | (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE if reloc_data else 0),
            0x100000,
            0x1000,
            0x100000,
            0x1000,
            0,
            16,
        )
    )
    directories = [(0, 0)] * 16
    if export_data:
        directories[IMAGE_DIRECTORY_ENTRY_EXPORT] = (export_rva, len(export_data))
    if import_data:
        directories[IMAGE_DIRECTORY_ENTRY_IMPORT] = (import_rva, import_size)
    if reloc_data:
        reloc_section = next(section for section in sections if section["name"] == b".reloc")
        directories[IMAGE_DIRECTORY_ENTRY_BASERELOC] = (
            reloc_section["rva"],
            reloc_section["virtual_size"],
        )
    optional.extend(b"".join(struct.pack("<II", *entry) for entry in directories))
    if len(optional) != PE_OPTIONAL_HEADER_SIZE:
        raise ConversionError("internal PE optional-header size mismatch")
    characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE
    if as_dll:
        characteristics |= IMAGE_FILE_DLL
    if not reloc_data:
        characteristics |= IMAGE_FILE_RELOCS_STRIPPED
    coff = PE_COFF_HEADER.pack(
        IMAGE_FILE_MACHINE_LOONGARCH64,
        len(sections),
        0,
        0,
        0,
        PE_OPTIONAL_HEADER_SIZE,
        characteristics,
    )
    section_headers = bytearray()
    for section in sections:
        name = section["name"][:8].ljust(8, b"\0")
        section_headers.extend(
            PE_SECTION_HEADER.pack(
                name,
                section["virtual_size"],
                section["rva"],
                section["raw_size"],
                section["raw_offset"],
                0,
                0,
                0,
                0,
                section["characteristics"],
            )
        )
    output = bytearray(raw_offset)
    output[:2] = b"MZ"
    struct.pack_into("<I", output, 0x3C, PE_HEADER_OFFSET)
    output[PE_HEADER_OFFSET : PE_HEADER_OFFSET + 4] = b"PE\0\0"
    header_offset = PE_HEADER_OFFSET + 4
    output[header_offset : header_offset + PE_COFF_HEADER.size] = coff
    header_offset += PE_COFF_HEADER.size
    output[header_offset : header_offset + PE_OPTIONAL_HEADER_SIZE] = optional
    header_offset += PE_OPTIONAL_HEADER_SIZE
    output[header_offset : header_offset + len(section_headers)] = section_headers
    for section in sections:
        data = bytes(section["data"])
        if data:
            output[section["raw_offset"] : section["raw_offset"] + len(data)] = data
    return output


def convert(args):
    image = ElfImage(args.input)
    dependencies = check_dynamic_dependencies(image)
    base_address = preferred_address(image, args.image_base)
    tables = symbol_tables(image)
    if args.entry is not None:
        try:
            image.entry = int(args.entry, 0)
        except ValueError:
            symbol = next(
                (
                    symbol
                    for table in tables.values()
                    for symbol in table
                    if symbol["name"] == args.entry and symbol["section"] != SHN_UNDEF
                ),
                None,
            )
            if symbol is None:
                raise ConversionError(f"entry symbol {args.entry} is not defined in the ELF image")
            image.entry = symbol["value"]
    import_map = {}
    if args.import_map:
        with open(args.import_map, "r", encoding="utf-8") as stream:
            import_map = json.load(stream)
        if not isinstance(import_map, dict) or any(
            not isinstance(symbol, str) or not isinstance(dll, str)
            for symbol, dll in import_map.items()
        ):
            raise ConversionError("import map must be a JSON object mapping symbols to DLL names")
    imports, import_relocations, got_accesses = collect_imports(
        image, tables, dependencies, import_map
    )
    max_rva = max(
        segment["address"] - image.base_address + image.rva_bias + segment["memory_size"]
        for segment in image.load_segments
    )
    import_rva = align(max_rva, SECTION_ALIGNMENT)
    import_data, iat_rvas, import_size = build_import_section(imports, import_rva)
    export_data = b""
    export_rva = 0
    if args.exports:
        module_name, exports = read_definition(args.exports)
        export_rva = align(import_rva + len(import_data), SECTION_ALIGNMENT)
        export_data, _ = build_export_section(
            image, tables, exports, module_name, export_rva
        )
    relocations = apply_relocations(
        image, tables, base_address, import_relocations, iat_rvas, got_accesses
    )
    output = build_pe(
        image,
        base_address,
        args.subsystem,
        args.dll,
        relocations,
        import_data,
        import_rva,
        import_size,
        export_data,
        export_rva,
    )
    with open(args.output, "wb") as stream:
        stream.write(output)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument("--image-base", type=lambda value: int(value, 0))
    parser.add_argument("--import-map")
    parser.add_argument("--exports")
    parser.add_argument("--entry")
    parser.add_argument(
        "--subsystem",
        type=lambda value: int(value, 0),
        default=IMAGE_SUBSYSTEM_NATIVE,
        choices=(
            IMAGE_SUBSYSTEM_NATIVE,
            IMAGE_SUBSYSTEM_WINDOWS_GUI,
            IMAGE_SUBSYSTEM_WINDOWS_CUI,
            IMAGE_SUBSYSTEM_POSIX_CUI,
            10,
            11,
            12,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION,
        ),
    )
    parser.add_argument("--dll", action="store_true")
    args = parser.parse_args()
    try:
        convert(args)
    except (ConversionError, OSError, UnicodeError, struct.error, ValueError, IndexError) as error:
        print(f"loongarch_elf_to_pe: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
