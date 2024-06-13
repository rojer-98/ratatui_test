use std::io::BufRead;

use object::read::elf::{SectionHeader, Sym};
use object::read::pe::ImageNtHeaders;
use object::Endianness;
use object::{elf::FileHeader64, read::elf::FileHeader};
use object::{pe::*, ReadRef};

const TEST_ELF: &'static [u8] = include_bytes!("../main");
const TEST_NT_LIB: &'static [u8] = include_bytes!("../my.sample.lib.dll");

pub fn check_object() {
    if let Ok(elf) = FileHeader64::<Endianness>::parse(TEST_ELF) {
        if let Ok(ss) = elf.sections(Endianness::Little, TEST_ELF) {
            let mut offsets = vec![];
            let mut index_table = vec![];
            for s in ss.iter() {
                if s.sh_type(Endianness::Little) == 0x2 {
                    if let Ok(Some(d)) =
                        s.symbols(Endianness::Little, TEST_ELF, &ss, object::SectionIndex(0))
                    {
                        index_table.push(d.string_section());
                        for sym in d.symbols().iter() {
                            let v = sym.st_value(Endianness::Little);
                            let n = sym.st_name(Endianness::Little);

                            println!("st_value: {v} == st_name: {n}");
                            offsets.push(sym.st_name(Endianness::Little));
                        }
                    }
                }
            }

            for s in ss.iter() {
                if s.sh_type(Endianness::Little) == 0x3 {
                    //println!("{s:#?}");

                    // if let Ok(rsd) = s.data(Endianness::Little, TEST_ELF) {
                    //     let data = rsd
                    //         .into_iter()
                    //         .fold(vec![], |mut acc, x| {
                    //             if *x != 0 {
                    //                 acc.push(*x)
                    //             } else {
                    //                 if let Some(l) = acc.last() {
                    //                     if *l != 0 {
                    //                         acc.push(0);
                    //                     }
                    //                 }
                    //             }
                    //
                    //             acc
                    //         })
                    //         .split(|x| *x == 0)
                    //         .into_iter()
                    //         .filter_map(|x| {
                    //             if let Ok(r) = String::from_utf8(x.to_vec()) {
                    //                 if r.len() > 0 {
                    //                     return Some(r);
                    //                 }
                    //             }
                    //
                    //             None
                    //         })
                    //         .collect::<Vec<_>>();
                    //
                    //     println!("{:?}", data);
                    // }

                    if let Ok(Some(d)) = s.strings(Endianness::Little, TEST_ELF) {
                        for o in offsets.iter() {
                            if let Ok(res) = d.get(*o) {
                                let val = String::from_utf8_lossy(res);
                                println!("{val:?}");
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
