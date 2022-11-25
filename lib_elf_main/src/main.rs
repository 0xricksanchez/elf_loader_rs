use lib_elf::*;
use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    //let path = Path::new("/bin/ls");
    let path = Path::new("../tests/bin/objdump.mips");
    let res = get_elf_header(path)?;
    match res {
        ELFHDR::ELF64(e64) => {
            println!("{}", ElfHeader64::elfhdr_to_str(&e64));
            let _phs = get_program_headers(&path)?;
            println!("{}", get_program_headers_as_str(&path));
        }
        ELFHDR::ELF32(e32) => {
            println!("{}", ElfHeader32::elfhdr_to_str(&e32));
            let _phs = get_program_headers(&path)?;
            println!("{}", get_program_headers_as_str(&path))
        }
    };
    Ok(())
}
