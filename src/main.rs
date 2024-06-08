mod keystone;
mod object;

use std::{error::Error, io, time::Duration, usize};

use capstone::prelude::*;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use keystone::check_keystone;
use object::check_object;
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style, Stylize},
    terminal::{Frame, Terminal},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

const X86_CODE: &'static [u8] = include_bytes!("../main.text");
const X64_CODE: &'static [u8] = b"\x41\xBC\x3B\xB0\x28\x2A\x49\x0F\xC9\x90\x4D\x0F\xAD\xCF\x49\x87\xFD\x90\x48\x81\xD2\x8A\xCE\x77\x35\x48\xF7\xD9\x4D\x29\xF4\x49\x81\xC9\xF6\x8A\xC6\x53\x4D\x87\xED\x48\x0F\xAD\xD2\x49\xF7\xD4\x48\xF7\xE1\x4D\x19\xC5\x4D\x89\xC5\x48\xF7\xD6\x41\xB8\x4F\x8D\x6B\x59\x4D\x87\xD0\x68\x6A\x1E\x09\x3C\x59";

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
                                let val =
                                    if key.modifiers == KeyModifiers::CONTROL && app.scroll >= 10 {
                                        10
                                    } else {
                                        1
                                    };

                                app.scroll -= val
                            }
                        }

                        KeyCode::Down => {
                            let val = if key.modifiers == KeyModifiers::CONTROL {
                                10
                            } else {
                                1
                            };

                            app.scroll += val
                        }
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

    let layout = Layout::horizontal([Constraint::Percentage(10), Constraint::Fill(1)]).split(size);

    let (ci, ads, op) = capstone();
    let ads = if (size.height - 2) as usize > ads.len() {
        ads
    } else {
        ads[app.scroll as usize..app.scroll as usize + size.height as usize - 2].to_vec()
    };
    let op = if (size.height - 2) as usize > op.len() {
        op
    } else {
        op[app.scroll as usize..app.scroll as usize + size.height as usize - 2].to_vec()
    };

    let create_block = |title| {
        Block::bordered()
            .style(Style::default().fg(Color::Gray))
            .title(Span::styled(
                title,
                Style::default().add_modifier(Modifier::BOLD),
            ))
    };

    let paragraph = Paragraph::new(ads)
        .style(Style::default().fg(Color::Gray))
        .block(create_block("Ads").borders(Borders::ALL))
        .centered();
    f.render_widget(paragraph, layout[0]);

    let paragraph = Paragraph::new(op)
        .style(Style::default().fg(Color::Gray))
        .block(create_block("Ins").borders(Borders::ALL));

    f.render_widget(paragraph, layout[1]);
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

fn capstone<'a>() -> (Line<'a>, Vec<Line<'a>>, Vec<Line<'a>>) {
    let mut addresses = vec![];
    let mut opcodes = vec![];

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let insns = cs
        .disasm_all(&X86_CODE, 0x1180)
        .expect("Failed to disassemble");

    let common_info = Line::from(format!("Found {} instructions", insns.len()));
    for i in insns.as_ref() {
        addresses.push(Line::from(format!("{:#010x}", i.address())));
        opcodes.push(Line::from(format!(
            "{} {}",
            i.mnemonic().unwrap_or_default(),
            i.op_str().unwrap_or_default()
        )));

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
    }

    (common_info, addresses, opcodes)
}

fn main() -> Result<(), Box<dyn Error>> {
    // // setup terminal
    // enable_raw_mode()?;
    // let mut stdout = io::stdout();
    // execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    // let backend = CrosstermBackend::new(stdout);
    // let mut terminal = Terminal::new(backend)?;
    //
    // // create app and run it
    // let tick_rate = Duration::from_millis(250);
    // let app = App::new();
    // let res = run_app(&mut terminal, app, tick_rate);
    //
    // // restore terminal
    // disable_raw_mode()?;
    // execute!(
    //     terminal.backend_mut(),
    //     LeaveAlternateScreen,
    //     DisableMouseCapture
    // )?;
    // terminal.show_cursor()?;
    //
    // if let Err(err) = res {
    //     println!("{err:?}");
    // }

    //check_object();
    check_keystone();
    Ok(())
}
