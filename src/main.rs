use std::{
    error::Error,
    io,
    path::Path,
    time::{Duration, Instant},
};

use capstone::prelude::*;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style, Stylize},
    terminal::{Frame, Terminal},
    text::{Line, Span},
    widgets::{Block, Paragraph, Wrap},
};
use xmas_elf::sections;
use xmas_elf::{header, program, ElfFile};

const X86_CODE: &'static [u8] = include_bytes!("../main.text");

struct App {
    scroll: u64,
}

impl App {
    const fn new() -> Self {
        Self { scroll: 0 }
    }
}

fn run_app<B: Backend>(
    terminal: &mut Terminal<B>,
    mut app: App,
    tick_rate: Duration,
) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &app))?;

        if crossterm::event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    return Ok(());
                }

                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Up => {
                            if app.scroll > 0 {
                                app.scroll -= 1
                            }
                        }
                        KeyCode::Down => app.scroll += 1,
                        _ => {}
                    }
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let size = f.size();

    // Words made "loooong" to demonstrate line breaking.
    let s = "Veeeeeeeeeeeeeeeery    loooooooooooooooooong   striiiiiiiiiiiiiiiiiiiiiiiiiing.   ";
    let mut long_line = s.repeat(usize::from(size.width) / s.len() + 4);
    long_line.push('\n');

    let block = Block::new().black();
    f.render_widget(block, size);

    let layout = Layout::vertical([Constraint::Fill(1)]).split(size);

    let text = capstone();

    let create_block = |title| {
        Block::bordered()
            .style(Style::default().fg(Color::Gray))
            .title(Span::styled(
                title,
                Style::default().add_modifier(Modifier::BOLD),
            ))
    };

    let paragraph = Paragraph::new(text[app.scroll as usize..].to_vec())
        .style(Style::default().fg(Color::Gray))
        .block(create_block("Default alignment (Left), no wrap"))
        .left_aligned()
        .wrap(Wrap { trim: false });
    f.render_widget(paragraph, layout[0]);
}

fn open_file<P: AsRef<Path>>(name: P) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut f = File::open(name).unwrap();
    let mut buf = Vec::new();
    assert!(f.read_to_end(&mut buf).unwrap() > 0);
    buf
}

fn display_binary_information<P: AsRef<Path>>(binary_path: P) {
    let buf = open_file(binary_path);
    let elf_file = ElfFile::new(&buf).unwrap();
    println!("{}", elf_file.header);
    header::sanity_check(&elf_file).unwrap();

    let mut sect_iter = elf_file.section_iter();
    // Skip the first (dummy) section
    sect_iter.next();
    println!("sections");
    for sect in sect_iter {
        println!("Name: {}", sect.get_name(&elf_file).unwrap());
        println!("Type: {:?}", sect.get_type());
        println!("Address: {:#x}", sect.address());
        // println!("{}", sect);
        sections::sanity_check(sect, &elf_file).unwrap();

        // if sect.get_type() == ShType::StrTab {
        //     println!("{:?}", sect.get_data(&elf_file).to_strings().unwrap());
        // }

        // if sect.get_type() == ShType::SymTab {
        //     if let sections::SectionData::SymbolTable64(data) = sect.get_data(&elf_file) {
        //         for datum in data {
        //             println!("{}", datum.get_name(&elf_file));
        //         }
        //     } else {
        //         unreachable!();
        //     }
        // }
    }
    let ph_iter = elf_file.program_iter();
    println!("\nprogram headers");
    for sect in ph_iter {
        println!("{:?}", sect.get_type());
        program::sanity_check(sect, &elf_file).unwrap();
    }

    match elf_file.program_header(5) {
        Ok(sect) => {
            println!("{}", sect);
            match sect.get_data(&elf_file) {
                Ok(program::SegmentData::Note64(header, ptr)) => {
                    println!("{}: {:?}", header.name(ptr), header.desc(ptr))
                }
                Ok(_) => (),
                Err(err) => println!("Error: {}", err),
            }
        }
        Err(err) => println!("Error: {}", err),
    }

    // let sect = elf_file.find_section_by_name(".rodata.const2794").unwrap();
    // println!("{}", sect);
}

/// Print register names
fn reg_names(cs: &Capstone, regs: &[RegId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.reg_name(x).unwrap()).collect();
    names.join(", ")
}

/// Print instruction group names
fn group_names(cs: &Capstone, regs: &[InsnGroupId]) -> String {
    let names: Vec<String> = regs.iter().map(|&x| cs.group_name(x).unwrap()).collect();
    names.join(", ")
}

fn capstone<'a>() -> Vec<Line<'a>> {
    let mut r = vec![];
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs
        .disasm_all(X86_CODE, 0x1180)
        .expect("Failed to disassemble");

    r.push(Line::from(format!("Found {} instructions", insns.len())));
    for i in insns.as_ref() {
        r.push(Line::from(format!("{i}")));

        let detail: InsnDetail = cs.insn_detail(&i).expect("Failed to get insn detail");
        let arch_detail: ArchDetail = detail.arch_detail();
        let ops = arch_detail.operands();

        let output: &[(&str, String)] = &[
            ("insn id:", format!("{:?}", i.id().0)),
            ("bytes:", format!("{:?}", i.bytes())),
            ("read regs:", reg_names(&cs, detail.regs_read())),
            ("write regs:", reg_names(&cs, detail.regs_write())),
            ("insn groups:", group_names(&cs, detail.groups())),
        ];

        for &(ref name, ref message) in output.iter() {
            //r.push(Line::from(format!("{:4}{:12} {}", "", name, message)));
        }

        r.push(Line::from(format!("{:4}operands: {}", "", ops.len())));
        for op in ops {
            //r.push(Line::from(format!("{:8}{:?}", "", op)));
        }
    }

    r
}

fn main() -> Result<(), Box<dyn Error>> {
    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // create app and run it
    let tick_rate = Duration::from_millis(250);
    let app = App::new();
    let res = run_app(&mut terminal, app, tick_rate);

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{err:?}");
    }

    Ok(())
}
