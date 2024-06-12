use object::pe::*;
use object::read::pe::ImageNtHeaders;
use object::Endianness;

const TEST_ELF: &'static [u8] = include_bytes!("../main");
const TEST_NT_LIB: &'static [u8] = include_bytes!("../my.sample.lib.dll");

pub fn check_object() {
    // if let Ok(elf) = FileHeader64::<Endianness>::parse(TEST_ELF) {
    //     let phs = elf
    //         .program_headers(elf.endian().unwrap_or(Endianness::Little), TEST_ELF)
    //         .unwrap();
    //     for ph in phs {
    //         println!("{ph:#?}");
    //     }
    // }

    if let Ok(nt) = ImageDosHeader::parse(TEST_NT_LIB) {
        println!("{nt:#?}");

        let mut offset = nt.nt_headers_offset().into();
        if let Ok((nt_headers, data_directories)) =
            ImageNtHeaders32::parse(TEST_NT_LIB, &mut offset)
        {
            println!("{nt_headers:#?}");
            println!("{data_directories:#?}");
        }
    }
}
