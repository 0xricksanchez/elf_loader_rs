// TODO: heavy refactoring needed once https://github.com/rust-lang/rust/issues/44580 is in stable
// Code can probably drastically reduced and de-duplicated when writing each functionality as a macro!

use core::fmt;
use std::io::{prelude::*, SeekFrom};
use std::{error::Error, fs, path::Path};

mod elf_utils;
use elf_utils::{
    e_abi_to_str, e_bit_to_str, e_class_to_str, e_machine_to_str, e_type_to_str, p_flags_to_str,
    p_type_to_str,
};

pub const EI_NIDENT: usize = 16;
pub const SIZEOF_EHDR32: usize = 54;
pub const SIZEOF_EHDR64: usize = 64;
pub const SIZEOF_PHDR32: usize = 32;
pub const SIZEOF_PHDR64: usize = 56;

pub enum ELFHDR {
    ELF32(ElfHeader32),
    ELF64(ElfHeader64),
}

// Brings in a nicer debugging output due to extra argument formatting
impl fmt::Debug for ELFHDR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ELFHDR::ELF32(e32) => f
                .debug_struct("32-Bit Header")
                .field("e_ident", &format_args!("{:x?}", e32.e_ident))
                .field("e_type", &format_args!("{:x?}", e32.e_type))
                .field("e_machine", &format_args!("0x{:x}", e32.e_machine))
                .field("e_version", &format_args!("0x{:x}", e32.e_version))
                .field("e_entry", &format_args!("0x{:x}", e32.e_entry))
                .field("e_phoff", &format_args!("0x{:x}", e32.e_phoff))
                .field("e_shoff", &format_args!("0x{:x}", e32.e_shoff))
                .field("e_flags", &format_args!("{:x}", e32.e_flags))
                .field("e_ehsize", &e32.e_ehsize)
                .field("e_phentsize", &e32.e_phentsize)
                .field("e_phnum", &e32.e_phnum)
                .field("e_shentsize", &e32.e_shentsize)
                .field("e_shnum", &e32.e_shnum)
                .field("e_shstrndx", &e32.e_shstrndx)
                .finish(),
            ELFHDR::ELF64(e64) => f
                .debug_struct("64-Bit Header")
                .field("e_ident", &format_args!("{:x?}", e64.e_ident))
                .field("e_type", &format_args!("{:x?}", e64.e_type))
                .field("e_machine", &format_args!("0x{:x}", e64.e_machine))
                .field("e_version", &format_args!("0x{:x}", e64.e_version))
                .field("e_entry", &format_args!("0x{:x}", e64.e_entry))
                .field("e_phoff", &format_args!("0x{:x}", e64.e_phoff))
                .field("e_shoff", &format_args!("0x{:x}", e64.e_shoff))
                .field("e_flags", &format_args!("{:x}", e64.e_flags))
                .field("e_ehsize", &e64.e_ehsize)
                .field("e_phentsize", &e64.e_phentsize)
                .field("e_phnum", &e64.e_phnum)
                .field("e_shentsize", &e64.e_shentsize)
                .field("e_shnum", &e64.e_shnum)
                .field("e_shstrndx", &e64.e_shstrndx)
                .finish(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ElfHeader32 {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u32,
    pub e_phoff: u32,
    pub e_shoff: u32,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ElfHeader64 {
    pub e_ident: [u8; EI_NIDENT],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

unsafe impl plain::Plain for ElfHeader32 {}
impl ElfHeader32 {
    /// Returns the Elf Header from a given byte array.
    fn get_elf_header(bytes: &[u8]) -> ElfHeader32 {
        let mut eh: ElfHeader32 = *plain::from_bytes(bytes).expect("Failed to get ELF header");
        *ElfHeader32::fix_header(&mut eh)
    }

    /// Converts all necessary fields to its `big endian` representation if needed
    fn fix_header(elf: &mut ElfHeader32) -> &ElfHeader32 {
        if elf.e_ident[0x5] == 2 {
            elf.e_type = elf.e_type.to_be();
            elf.e_machine = elf.e_machine.to_be();
            elf.e_version = elf.e_version.to_be();
            elf.e_entry = elf.e_entry.to_be();
            elf.e_phoff = elf.e_phoff.to_be();
            elf.e_shoff = elf.e_shoff.to_be();
            //elf.e_flags = elf.e_flags.to_be();
            elf.e_ehsize = elf.e_ehsize.to_be();
            elf.e_phentsize = elf.e_phentsize.to_be();
            elf.e_phnum = elf.e_phnum.to_be();
            elf.e_shentsize = elf.e_shentsize.to_be();
            elf.e_shnum = elf.e_shnum.to_be();
            elf.e_shstrndx = elf.e_shstrndx.to_be();
            elf
        } else {
            elf
        }
    }

    /// Returns a string representation of a given elf header
    pub fn elfhdr_to_str(elf_header: &ElfHeader32) -> String {
        let s = format!(
            "ELF Header:
  {:34} {:x?}
  {:34} {}
  {:34} {}
  {:34} {}
  {:34} {}
  {:34} {}
  {:34} 0x{:x}
  {:34} 0x{:x}
  {:34} 0x{:x}
  {:34} {} (in bytes)
  {:34} {} (in bytes)
  {:34} {}
  {:34} {}
  {:34} {:x}
  {:34} {}
  ",
            "Magic:",
            elf_header.e_ident,
            "Class:",
            e_class_to_str(elf_header.e_ident[0x4]),
            "Endianess:",
            e_bit_to_str(elf_header.e_ident[0x5]),
            "ABI:",
            e_abi_to_str(elf_header.e_ident[0x7]),
            "Binary type:",
            e_type_to_str(elf_header.e_type),
            "Machine:",
            e_machine_to_str(elf_header.e_machine),
            "Entry point:",
            elf_header.e_entry,
            "Program headers offset:",
            elf_header.e_phoff,
            "Section headers offset:",
            elf_header.e_shoff,
            "Size of program header table:",
            elf_header.e_phentsize,
            "Size of section header table:",
            elf_header.e_shentsize,
            "Number of program headers:",
            elf_header.e_phnum,
            "Number of section headers:",
            elf_header.e_shnum,
            "Flags",
            elf_header.e_flags,
            "Section header string table index:",
            elf_header.e_shstrndx,
        );
        s
    }
}

unsafe impl plain::Plain for ElfHeader64 {}
impl ElfHeader64 {
    /// Returns the Elf Header from a given byte array.
    fn get_elf_header(bytes: &[u8]) -> ElfHeader64 {
        let mut eh: ElfHeader64 = *plain::from_bytes(bytes).expect("Failed to get ELF header");
        *ElfHeader64::fix_header(&mut eh)
    }

    /// Converts all necessary fields to its `big endian` representation if needed
    fn fix_header(elf: &mut ElfHeader64) -> &ElfHeader64 {
        if elf.e_ident[0x5] == 2 {
            elf.e_type = elf.e_type.to_be();
            elf.e_machine = elf.e_machine.to_be();
            elf.e_version = elf.e_version.to_be();
            elf.e_entry = elf.e_entry.to_be();
            elf.e_phoff = elf.e_phoff.to_be();
            elf.e_shoff = elf.e_shoff.to_be();
            elf.e_flags = elf.e_flags.to_be();
            elf.e_ehsize = elf.e_ehsize.to_be();
            elf.e_phentsize = elf.e_phentsize.to_be();
            elf.e_phnum = elf.e_phnum.to_be();
            elf.e_shentsize = elf.e_shentsize.to_be();
            elf.e_shnum = elf.e_shnum.to_be();
            elf.e_shstrndx = elf.e_shstrndx.to_be();
            elf
        } else {
            elf
        }
    }

    /// Returns a string representation of a given elf header
    pub fn elfhdr_to_str(elf_header: &ElfHeader64) -> String {
        let s = format!(
            "ELF Header:
  {:34} {:x?}
  {:34} {}
  {:34} {}
  {:34} {}
  {:34} {}
  {:34} {}
  {:34} 0x{:x}
  {:34} 0x{:x}
  {:34} 0x{:x}
  {:34} {} (in bytes)
  {:34} {} (in bytes)
  {:34} {}
  {:34} {}
  {:34} {:x}
  {:34} {}
  ",
            "Magic:",
            elf_header.e_ident,
            "Class:",
            e_class_to_str(elf_header.e_ident[0x4]),
            "Endianess:",
            e_bit_to_str(elf_header.e_ident[0x5]),
            "ABI:",
            e_abi_to_str(elf_header.e_ident[0x7]),
            "Binary type:",
            e_type_to_str(elf_header.e_type),
            "Machine:",
            e_machine_to_str(elf_header.e_machine),
            "Entry point:",
            elf_header.e_entry,
            "Program headers offset:",
            elf_header.e_phoff,
            "Section headers offset:",
            elf_header.e_shoff,
            "Size of program header table:",
            elf_header.e_phentsize,
            "Size of section header table:",
            elf_header.e_shentsize,
            "Number of program headers:",
            elf_header.e_phnum,
            "Number of section headers:",
            elf_header.e_shnum,
            "Flags",
            elf_header.e_flags,
            "Section header string table index:",
            elf_header.e_shstrndx,
        );
        s
    }
}

#[derive(Debug)]
pub enum PHS {
    PH32(Vec<ProgramHeader32>),
    PH64(Vec<ProgramHeader64>),
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramHeader32 {
    p_type: u32,
    p_offset: u32,
    p_vaddr: u32,
    p_paddr: u32,
    p_filesz: u32,
    p_memsz: u32,
    p_flags: u32,
    p_align: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProgramHeader64 {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

unsafe impl plain::Plain for ProgramHeader32 {}
impl ProgramHeader32 {
    fn fix_program_header(ph: &mut ProgramHeader32, bit: u8) -> &ProgramHeader32 {
        if bit == 2 {
            ph.p_type = ph.p_type.to_be();
            ph.p_flags = ph.p_flags.to_be();
            ph.p_offset = ph.p_offset.to_be();
            ph.p_vaddr = ph.p_vaddr.to_be();
            ph.p_paddr = ph.p_paddr.to_be();
            ph.p_filesz = ph.p_filesz.to_be();
            ph.p_memsz = ph.p_memsz.to_be();
            //ph.p_flags = ph.p_flags.to_be();
            ph.p_align = ph.p_align.to_be();
            ph
        } else {
            ph
        }
    }

    fn get_ph(bytes: &[u8]) -> &ProgramHeader32 {
        plain::from_bytes(bytes).expect("Failed to get ELF32 program header")
    }

    fn get_program_headers<P: AsRef<Path>>(
        elf_bin: P,
    ) -> Result<Vec<ProgramHeader32>, Box<dyn Error>>
    where
        P: Copy,
    {
        let hdr = get_elf_header(&elf_bin)?;
        if let ELFHDR::ELF32(elf) = hdr {
            let mut pharr: Vec<ProgramHeader32> = vec![Default::default(); elf.e_phnum as usize];
            let mut f = fs::File::open(elf_bin)?;
            for i in 0..elf.e_phnum {
                let mut ph_buf: Vec<u8> = vec![0; SIZEOF_PHDR32];
                let offset = i as i64 * elf.e_phentsize as i64;
                f.seek(SeekFrom::Start(offset as u64 + elf.e_phoff as u64))?;
                f.read_exact(&mut ph_buf[..])?;
                pharr[i as usize] = *ProgramHeader32::fix_program_header(
                    &mut ProgramHeader32::get_ph(&ph_buf).to_owned(),
                    elf.e_ident[0x5],
                );
            }
            Ok(pharr)
        } else {
            panic!("Failed to get ELF header to process program header!")
        }
    }

    fn get_program_headers_as_str<P: AsRef<Path>>(elf_bin: P) -> String {
        let hdr = ElfHeader32::get_elf_header(&fs::read(&elf_bin).unwrap());
        let ph = ProgramHeader32::get_program_headers(&elf_bin).unwrap();
        let mut s = format!(
            "Located {} program headers:
  {:20}{:20}{:20}{:20}
  {:20}{:20}{:20}{:10}{:10}
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n",
            ph.len(),
            "Type",
            "Offset",
            "VirtAddr",
            "PhysAddr",
            "",
            "FileSize",
            "MemSize",
            "Flags",
            "Align",
        );
        for p in ph.iter() {
            let g = format!(
                "{:22}0x{:<18.1x}0x{:<18.1x}0x{:x}\n{:22}0x{:<18.1x}0x{:<18.1x}{:<10.3}0x{:x}\n",
                p_type_to_str(p.p_type, hdr.e_machine),
                p.p_offset,
                p.p_vaddr,
                p.p_paddr,
                "",
                p.p_filesz,
                p.p_memsz,
                p_flags_to_str(p.p_flags),
                p.p_align
            );
            s.push_str(&g);
            s.push_str(
                "______________________________________________________________________________\n",
            );
        }
        s
    }
}

unsafe impl plain::Plain for ProgramHeader64 {}
impl ProgramHeader64 {
    fn fix_program_header(ph: &mut ProgramHeader64, bit: u8) -> &ProgramHeader64 {
        if bit == 2 {
            ph.p_type = ph.p_type.to_be();
            ph.p_flags = ph.p_flags.to_be();
            ph.p_offset = ph.p_offset.to_be();
            ph.p_vaddr = ph.p_vaddr.to_be();
            ph.p_paddr = ph.p_paddr.to_be();
            ph.p_filesz = ph.p_filesz.to_be();
            ph.p_memsz = ph.p_memsz.to_be();
            //ph.p_flags = ph.p_flags.to_be();
            ph.p_align = ph.p_align.to_be();
            ph
        } else {
            ph
        }
    }

    fn get_ph(bytes: &[u8]) -> &ProgramHeader64 {
        plain::from_bytes(bytes).expect("Failed to get ELF64 program header")
    }

    fn get_program_headers<P: AsRef<Path>>(
        elf_bin: P,
    ) -> Result<Vec<ProgramHeader64>, Box<dyn Error>>
    where
        P: Copy,
    {
        let hdr = get_elf_header(&elf_bin)?;
        if let ELFHDR::ELF64(elf) = hdr {
            let mut pharr: Vec<ProgramHeader64> = vec![Default::default(); elf.e_phnum as usize];
            let mut f = fs::File::open(elf_bin)?;
            for i in 0..elf.e_phnum {
                let mut ph_buf: Vec<u8> = vec![0; SIZEOF_PHDR64];
                let offset = i as i64 * elf.e_phentsize as i64;
                f.seek(SeekFrom::Start(offset as u64 + elf.e_phoff))?;
                f.read_exact(&mut ph_buf[..])?;
                pharr[i as usize] = *ProgramHeader64::fix_program_header(
                    &mut ProgramHeader64::get_ph(&ph_buf).to_owned(),
                    elf.e_ident[0x5],
                );
            }
            Ok(pharr)
        } else {
            panic!("Failed to get ELF header to process program header!")
        }
    }
    fn get_program_headers_as_str<P: AsRef<Path>>(elf_bin: P) -> String {
        let hdr = ElfHeader64::get_elf_header(&fs::read(&elf_bin).unwrap());
        let ph = ProgramHeader64::get_program_headers(&elf_bin).unwrap();
        let mut s = format!(
            "Located {} program headers:
  {:20}{:20}{:20}{:20}
  {:20}{:20}{:20}{:10}{:10}
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n",
            ph.len(),
            "Type",
            "Offset",
            "VirtAddr",
            "PhysAddr",
            "",
            "FileSize",
            "MemSize",
            "Flags",
            "Align",
        );
        for p in ph.iter() {
            let g = format!(
                "{:22}0x{:<18.1x}0x{:<18.1x}0x{:x}\n{:22}0x{:<18.1x}0x{:<18.1x}{:<10.3}0x{:x}\n",
                p_type_to_str(p.p_type, hdr.e_machine),
                p.p_offset,
                p.p_vaddr,
                p.p_paddr,
                "",
                p.p_filesz,
                p.p_memsz,
                p_flags_to_str(p.p_flags),
                p.p_align
            );
            s.push_str(&g);
            s.push_str(
                "______________________________________________________________________________\n",
            );
        }
        s
    }
}

/// Attempts to read all program headers from a given ELF binary (path)
/// The **caller** is responsible for handling the return value properly.
pub fn get_program_headers<P: AsRef<Path>>(elf_path: P) -> Result<PHS, Box<dyn Error>> {
    let mut bits = vec![0_u8, 1];
    let mut f = fs::File::open(&elf_path)?;
    f.seek(SeekFrom::Start(0x4))?;
    f.read_exact(&mut bits)?;
    let bits = bits[0] as u8;
    if bits == 1 {
        Ok(PHS::PH32(ProgramHeader32::get_program_headers(&elf_path)?))
    } else {
        Ok(PHS::PH64(ProgramHeader64::get_program_headers(&elf_path)?))
    }
}

/// Returns a formatted and parsed program header table for a given ELF binary (path)
/// as its string representation
pub fn get_program_headers_as_str<P: AsRef<Path>>(elf_bin: P) -> String {
    let mut bits = vec![0_u8, 1];
    let mut f = fs::File::open(&elf_bin).unwrap();
    f.seek(SeekFrom::Start(0x4)).unwrap();
    f.read_exact(&mut bits).unwrap();
    let bits = bits[0] as u8;
    if bits == 1 {
        ProgramHeader32::get_program_headers_as_str(&elf_bin)
    } else {
        ProgramHeader64::get_program_headers_as_str(&elf_bin)
    }
}

/// Attempts to read the ELF header information from a given ELF binary (path)
/// The **caller** is responsible for handling the return value properly.
pub fn get_elf_header<P: AsRef<Path>>(elf_path: P) -> Result<ELFHDR, Box<dyn Error>>
where
    P: Copy,
{
    let mut bits = vec![0_u8, 1];
    let mut f = fs::File::open(elf_path)?;
    f.seek(SeekFrom::Start(0x4))?;
    f.read_exact(&mut bits)?;
    let bits = bits[0] as u8;
    let contents = fs::read(elf_path)?;
    if bits == 1 {
        Ok(ELFHDR::ELF32(ElfHeader32::get_elf_header(&contents)))
    } else {
        Ok(ELFHDR::ELF64(ElfHeader64::get_elf_header(&contents)))
    }
}

/// Returns a formatted and parsed ELF header for a given ELF binary (path)
/// as its string representation
pub fn get_elf_header_as_str<P: AsRef<Path>>(elf_path: P) -> String {
    let res = get_elf_header(&elf_path).unwrap();
    match res {
        ELFHDR::ELF64(e64) => ElfHeader64::elfhdr_to_str(&e64),
        ELFHDR::ELF32(e32) => ElfHeader32::elfhdr_to_str(&e32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x64_e_magic() {
        let path = Path::new("/bin/ls");
        let res = get_elf_header(path).unwrap();
        match res {
            ELFHDR::ELF64(e64) => {
                let expected_magic: [u8; 16] = [
                    0x7f, 0x45, 0x4c, 0x46, 0x2, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                    0x0,
                ];
                let actual_magic = e64.e_ident;
                assert_eq!(expected_magic, actual_magic);
                assert_eq!(expected_magic.len(), actual_magic.len());
            }
            _ => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_x64_e_machine() {
        let path = Path::new("/bin/ls");
        let res = get_elf_header(path).unwrap();
        match res {
            ELFHDR::ELF64(e64) => {
                let expected = "AMD x86-64 architecture";
                let actual = e_machine_to_str(e64.e_machine);
                assert_eq!(expected, actual);
            }
            _ => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_x64_e_endianness() {
        let path = Path::new("/bin/ls");
        let res = get_elf_header(path).unwrap();
        match res {
            ELFHDR::ELF64(e64) => {
                let expected = "little endian";
                let actual = e_bit_to_str(e64.e_ident[0x5]).to_lowercase();
                assert_eq!(expected, actual);
            }
            _ => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_x64_number_phs() {
        let path = Path::new("/bin/ls");
        let res = get_program_headers(path).unwrap();
        match res {
            PHS::PH64(ph64) => {
                let expected = 13;
                let actual = ph64.len();
                assert_eq!(expected, actual);
            }
            _ => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_arm_number_phs() {
        let path = Path::new("tests/bin/dd.armel");
        let res = get_program_headers(path).unwrap();
        match res {
            PHS::PH32(ph32) => {
                let expected = 6;
                let actual = ph32.len();
                assert_eq!(expected, actual);
            }
            _ => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_arm_specific_ph() {
        let path = Path::new("tests/bin/dd.armel");
        let content = fs::read(path).unwrap();
        let hdr = ElfHeader32::get_elf_header(&content);
        let res = get_program_headers(path).unwrap();
        match res {
            PHS::PH32(ph32) => {
                let expected = "PT_ARM_EXIDX";
                let actual = p_type_to_str(ph32[0].p_type, hdr.e_machine);
                assert_eq!(expected, actual);
            }
            _ => assert_eq!(1, 0),
        }
    }

    #[test]
    fn test_mips_specific_ph() {
        let path = Path::new("tests/bin/objdump.mips");
        let content = fs::read(path).unwrap();
        let hdr = ElfHeader32::get_elf_header(&content);
        let res = get_program_headers(path).unwrap();
        match res {
            PHS::PH32(ph32) => {
                let expected = "PT_MIPS_REGINFO";
                let actual = p_type_to_str(ph32[1].p_type, hdr.e_machine);
                assert_eq!(expected, actual);
            }
            _ => assert_eq!(1, 0),
        }
    }
}
