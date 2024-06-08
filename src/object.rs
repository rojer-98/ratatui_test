use object::elf::*;
use object::read::elf::*;
use object::read::{SectionIndex, StringTable, SymbolIndex};
use object::Endianness;

const TEST_ELF: &'static [u8] = include_bytes!("../main");

pub fn check_object() {
    if let Ok(elf) = FileHeader64::<Endianness>::parse(TEST_ELF) {
        let phs = elf
            .program_headers(elf.endian().unwrap_or(Endianness::Little), TEST_ELF)
            .unwrap();
        for ph in phs {
            println!("{ph:#?}");
        }
    }
}
