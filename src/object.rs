use object::pe::*;
use object::read::elf::{SectionHeader, Sym};
use object::read::pe::ImageNtHeaders;
use object::Endianness;
use object::{elf::FileHeader64, read::elf::FileHeader};

const TEST_ELF: &'static [u8] = include_bytes!("../main");
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
                        for sym in d.symbols().iter() {
                            offsets.push(sym.st_name(Endianness::Little));
                        }
                    }
                }
            }

            for s in ss.iter() {
                if s.sh_type(Endianness::Little) == 0x3 {
                    //println!("{s:#?}");

                    if let Ok(Some(d)) = s.strings(Endianness::Little, TEST_ELF) {
                        for o in offsets.iter() {
                            if let Ok(res) = d.get(*o) {
                                println!("{:?}", String::from_utf8(res.to_vec()));
                            }
                        }
                    }
                }
            }
        }
        let phs = elf
            .program_headers(elf.endian().unwrap_or(Endianness::Little), TEST_ELF)
            .unwrap();
        for ph in phs {
            //println!("{ph:#?}");
        }
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
