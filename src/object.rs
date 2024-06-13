use std::io::BufRead;

use object::read::elf::{SectionHeader, Sym};
use object::read::pe::ImageNtHeaders;
use object::Endianness;
use object::{elf::FileHeader64, read::elf::FileHeader};
use object::{pe::*, ReadRef};

const TEST_ELF: &'static [u8] = include_bytes!("../main_debug_dwarf");
const TEST_NT_LIB: &'static [u8] = include_bytes!("../my.sample.lib.dll");

pub fn check_object() {
    if let Ok(elf) = FileHeader64::<Endianness>::parse(TEST_ELF) {
        if let Ok(ss) = elf.sections(Endianness::Little, TEST_ELF) {
            let mut offsets = vec![];

            for s in ss.iter() {
                if s.sh_type(Endianness::Little) == 0x2 {
                    if let Ok(Some(d)) =
                        s.symbols(Endianness::Little, TEST_ELF, &ss, object::SectionIndex(0))
                    {
                        let mut res = vec![];
                        for sym in d.symbols().iter() {
                            res.push(sym.st_name(Endianness::Little));
                        }

                        offsets.push((d.string_section(), res));
                    }
                }
            }

            for (i, off) in offsets {
                if let Ok(d) = ss.strings(Endianness::Little, TEST_ELF, i) {
                    for o in off.iter() {
                        if let Ok(res) = d.get(*o) {
                            let val = String::from_utf8(res.to_vec());
                            println!("{val:?}");
                        }
                    }
                }
            }
        }

        let phs = elf
            .program_headers(elf.endian().unwrap_or(Endianness::Little), TEST_ELF)
            .unwrap();
    }

    // if let Ok(nt) = ImageDosHeader::parse(TEST_NT_LIB) {
    //     println!("{nt:#?}");
    //
    //     let mut offset = nt.nt_headers_offset().into();
    //     if let Ok((nt_headers, data_directories)) =
    //         ImageNtHeaders32::parse(TEST_NT_LIB, &mut offset)
    //     {
    //         println!("{nt_headers:#?}");
    //         println!("{data_directories:#?}");
    //     }
    // }
}
