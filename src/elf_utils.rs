/// Returns a human readable string representation for the E_CLASS field
pub fn e_class_to_str(c: u8) -> &'static str {
    match c {
        1 => "ELF32",
        2 => "ELF64",
        _ => "Unknown",
    }
}

/// Returns a human readable string representation for the E_BIT field
pub fn e_bit_to_str(c: u8) -> &'static str {
    match c {
        1 => "Little endian",
        2 => "Big endian",
        _ => "Unknown,",
    }
}

/// Returns a human readable string representation for the E_TYPE field
/// We assume `c` has the correct endianness
pub fn e_type_to_str(c: u16) -> &'static str {
    match c {
        0 => "No file type",
        1 => "Relocatable file",
        2 => "Executable file",
        3 => "Shared object file",
        4 => "Core file",
        0xfe00 | 0xfeff => "Operating system-specfic",
        0xff00 | 0xffff => "Processor-specific",
        _ => "Unknown",
    }
}

/// Returns a human readable string representation for the E_ABI field
pub fn e_abi_to_str(c: u8) -> &'static str {
    match c {
        0 => "System V",
        1 => "HP-UX",
        2 => "NetBSD",
        3 => "Linux",
        4 => "GNU Hurd",
        6 => "Solaris",
        7 => "AIX",
        8 => "IRIX",
        9 => "FreeBSD",
        10 => "Tru64",
        11 => "Novell Modesto",
        12 => "OpenBSD",
        13 => "OpenVMS",
        14 => "NonStop Kernel",
        15 => "AROS",
        16 => "Fenix OS",
        17 => "CloudABI",
        18 => "Stratus Technologies OpenVOS",
        _ => "Unknown",
    }
}

/// Returns a human readable string representation for the E_MACHINE field
/// We assume `c` has the correct endianness
pub fn e_machine_to_str(c: u16) -> &'static str {
    match c {
        0 => "No machine",
        1 => "AT&T WE 32100",
        2 => "SUN SPARC",
        3 => "Intel 80386",
        4 => "Motorola 68000",
        5 => "Motorola 88000",
        7 => "Intel 80860",
        8 => "MIPS R3000 big-endian",
        15 => "Hewlett-Packard PA-RISC",
        18 => "Enhanced instruction set SPARC",
        20 => "PowerPC",
        21 => "PowerPC64",
        22 => "IBM S/390",
        23 => "Cell BE SPU",
        40 => "Advanced RISC Machines ARM",
        41 => "Digital Alpha",
        42 => "Hitachi SH",
        43 => "SPARC Version 9 64-bit",
        46 => "Renesas H8/300",
        50 => "Intel IA-64 processor architecture",
        62 => "AMD x86-64 architecture",
        76 => "Axis Communications 32-bit embedded processor",
        88 => "Renesas M32R",
        89 => "Panasonic/MEI MN10300, AM33",
        92 => "OpenRISC 32-bit embedded processor",
        93 => "ARC Cores Tangent-A5",
        94 => "Tensilica Xtensa Architecture",
        106 => "ADI Blackfin processor",
        110 => "UniCore-32",
        113 => "Altera Nios II soft-core processor",
        140 => "TMS320C6000 Family",
        164 => "QUALCOMM Hexagon",
        167 => "Andes Technology embedded RISC processor",
        183 => "ARM 64-bits (ARMv8/Aarch64)",
        188 => "Tilera TILE-Gx",
        195 => "ARCv2 Cores",
        243 => "RISC-V",
        247 => "Linux BPF",
        252 => "C-SKY",
        _ => "Unknown",
    }
}

/// Returns a human readable string representation for the P_FLAGS field
/// We assume `c` has the correct endianness
pub fn p_flags_to_str(c: u32) -> &'static str {
    match c {
        1 => "X",
        2 => "W",
        3 => " WX",
        4 => "R",
        5 => "R X",
        6 => "RW",
        7 => "RWX",
        _ => "???",
    }
}

/// Returns a human readable string representation for the P_TYPE field
/// We assume `c` has the correct endianness
pub fn p_type_to_str(c: u32, d: u16) -> &'static str {
    let arch = e_machine_to_str(d).to_lowercase();
    match c {
        0 => "PT_NULL",
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x60000000 => "PT_LOOS",
        0x6FFFFFFF => "PT_HIOS",
        0x7FFFFFFF => "PT_HIPROC",
        0x6474e553 => "GNU_PROPERTY",
        0x6474e550 => "GNU_EH_FRAME",
        0x6474e551 => "GNU_STACK",
        0x6474e552 => "GNU_RELRO",
        0x70000000 => {
            if arch.contains("arm") {
                "APT_ARM_ARCHEXT"
            } else if arch.contains("mips") {
                "PT_MIPS_REGINFO"
            } else {
                "PT_LOPROC"
            }
        }
        0x70000001 => {
            if arch.contains("arm") {
                "PT_ARM_EXIDX"
            } else {
                "PT_MIPS_RTPROC"
            }
        }
        0x70000002 => "PT_MIPS_OPTIONS",
        0x70000003 => "PT_MIPS_ABI_FLAGS",
        _ => "Unknown",
    }
}
