use std::collections::HashMap;

use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use crate::inferior::{Inferior, Status};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use std::fs::File;
use std::io::{self, BufRead}; // self = std::io.

#[derive(Clone)]
pub struct Breakpoint {
    pub num: usize,    // the number of this breakpoint.
    pub addr: usize,   // the address where the breakpoint is set.
    pub orig_byte: u8, // the original byte replaced by "0xcc".
}

pub struct Debugger {
    target: String,       // the path of the target program to be debugged.
    history_path: String, // the path to store history entries, i.e. commands you have typed into the debugger.
    readline: Editor<()>,
    // an inferior wraps a process being traced by the debugger.
    // it acts like an interface for the debugger to manipulate the tracee.
    inferior: Option<Inferior>,
    // contains debugging symbols (e.g. line numbers, variable names, function names),
    // and utility functions to extract these symbols.
    debug_data: DwarfData,
    breakpoints: HashMap<usize, Breakpoint>, // key: addr, val: breakpoint.
    next_bp_num: usize,                      // next breakpoint number.
}

fn parse_address(addr: &str) -> Option<usize> {
    let addr_without_0x = if addr.to_lowercase().starts_with("0x") {
        &addr[2..]
    } else {
        &addr
    };
    usize::from_str_radix(addr_without_0x, 16).ok()
}

fn print_source_line(file_path: &str, line_number: usize) {
    // open the file.
    let file = File::open(file_path).expect("error open file");
    // note, to use lines(), you need to import BufRead trait.
    let lines = io::BufReader::new(file).lines();
    // print the line_number-th line in the file.
    let mut i = 1; // line numbers start from 1.
    for line in lines {
        if let Ok(line) = line {
            if i == line_number {
                println!("Source: {}", line);
            }
        } else {
            println!("Error reading line");
            break;
        }
        i += 1;
    }
    // the file is dropped/closed when out of scope.
}

impl Debugger {
    /// Initializes the debugger.
    pub fn new(target: &str) -> Debugger {
        let debug_data = match DwarfData::from_file(target) {
            Ok(val) => val,
            Err(DwarfError::ErrorOpeningFile) => {
                println!("Could not open file {}", target);
                std::process::exit(1);
            }
            Err(DwarfError::DwarfFormatError(err)) => {
                println!("Could not debugging symbols from {}: {:?}", target, err);
                std::process::exit(1);
            }
        };

        debug_data.print();

        let history_path = format!("{}/.deet_history", std::env::var("HOME").unwrap());
        let mut readline = Editor::<()>::new();
        // Attempt to load history from ~/.deet_history if it exists
        let _ = readline.load_history(&history_path);

        Debugger {
            target: target.to_string(),
            history_path,
            readline,
            inferior: None,
            debug_data,
            breakpoints: HashMap::new(),
            next_bp_num: 0,
        }
    }

    // when this function is called, the inferior must be the stopped state.
    pub fn cont_inferior(&mut self) {
        let pid = self.inferior.as_ref().unwrap().pid();
        let regs = ptrace::getregs(pid).expect("error getregs");
        // the address one byte before the instruction pointer.
        let addr = regs.rip as usize - 1;

        if let Some(bp) = self.breakpoints.get_mut(&addr) {
            // when the inferior is previously stopped due to a breakpoint,
            // the resuming procedure consists of two phases:
            // (1) step the inferior one instruction forward and then make it stop by sending it a SIGTRAP signal.
            // (2) if the inferior does not exit, resume the inferior.

            // note, if enter this branch, the original byte replaced by this breakpoint
            // must have already been restored.
            // so we can safely step the inferior.

            // the inferior will execute one instruction and then interrupted by the SIGTRAP signal.
            ptrace::step(pid, Signal::SIGTRAP).expect("error step");
            // wait for the inferior to stop.
            let res = self.inferior.as_mut().unwrap().wait(None);
            match res {
                Ok(Status::Stopped(signal, _)) => {
                    if signal == Signal::SIGTRAP {
                        // reinstall the breakpoint.
                        self.inferior.as_mut().unwrap().install_breakpoint(bp);
                    } else {
                        println!(
                            "Error inferiror stepped but interrupted by signal {}",
                            signal
                        );
                        return;
                    }
                }
                Ok(Status::Exited(_)) => {
                    drop(self.inferior.as_mut().unwrap());
                    self.inferior = None;
                    println!("Child exited (status 0)");
                    return;
                }
                _ => {
                    println!("process {} encounters error on cont", pid);
                    return;
                }
            }
        }

        // resume the inferior process.
        // cont() is returned when the wait syscall captures the stopped or exited inferior.
        let res = self.inferior.as_mut().unwrap().cont();
        match res {
            Ok(Status::Stopped(signal, instruction_ptr)) => {
                // the instruction pointer register, aka. program counter, holds the
                // address of the next instruction to be executed.
                // when we hit a breakpoint, i.e. the CPU executes the 0xcc instruction,
                // the instruction pointer will hold the address of the instruction
                // immediately next to the 0xcc instruction.
                // so, to get the address of the breakpoint, we need to offset this address
                // by -1 byte.
                let addr = instruction_ptr - 1;
                if let Some(bp) = self.breakpoints.get(&addr) {
                    println!("Hit breakpoint {} at {:#x}", bp.num, addr);

                    // restore the original byte replaced by "0xcc".
                    self.inferior.as_mut().unwrap().restore_orig_byte(bp);
                    // rewind/backoff the instruction pointer, i.e. make it holds the address of the
                    // restored original byte, which one byte before the current instruction pointer, aka. rip.
                    let mut regs = ptrace::getregs(pid).expect("error getregs");
                    regs.rip -= 1;
                    ptrace::setregs(pid, regs).expect("error setregs");
                }

                println!("Child stopped (signal {:?})", signal);

                // print current stack frame.
                let regs = ptrace::getregs(pid).expect("error getregs");
                let line = self.debug_data.get_line_from_addr(regs.rip as usize);
                let func_name = self.debug_data.get_function_from_addr(regs.rip as usize);
                if line.is_some() && func_name.is_some() {
                    println!(
                        "Stopped at ({}:{}) in {}",
                        line.as_ref().unwrap().file,
                        line.as_ref().unwrap().number,
                        func_name.as_ref().unwrap()
                    );
                    // print the source code corresponding to current line.
                    print_source_line(
                        line.as_ref().unwrap().file.as_str(),
                        line.as_ref().unwrap().number,
                    );
                }
            }
            Ok(Status::Exited(_)) => {
                drop(self.inferior.as_mut().unwrap());
                self.inferior = None;
                println!("Child exited (status 0)");
            }
            _ => {
                println!("process {} encounters error on cont", pid);
            }
        }
    }

    // FIXME: capture the error.
    pub fn kill_inferior(&mut self) {
        println!(
            "killing running inferior (pid {})",
            self.inferior.as_ref().unwrap().pid()
        );

        if let Err(_) = self.inferior.as_mut().unwrap().kill() {
            println!("Error kill");
            return;
        }
        drop(self.inferior.as_mut().unwrap());
        self.inferior = None;
    }

    pub fn run(&mut self) {
        loop {
            match self.get_next_command() {
                DebuggerCommand::Run(args) => {
                    if self.inferior.is_some() {
                        self.kill_inferior();
                    }

                    // create a new inferior.
                    // the inferior is initially at the stopped state because of SIGTRAP.
                    if let Some(inferior) = Inferior::new(&self.target, &args) {
                        self.inferior = Some(inferior);
                        // install all breakpoints.
                        for bp in self.breakpoints.values_mut() {
                            self.inferior.as_mut().unwrap().install_breakpoint(bp);
                        }
                        // resume the inferior.
                        self.cont_inferior();
                    } else {
                        println!("Error: failed to start inferior");
                    }
                }
                DebuggerCommand::Cont => {
                    if self.inferior.is_none() {
                        println!("Error: no inferior");
                        return;
                    }
                    self.cont_inferior();
                }
                DebuggerCommand::Back => {
                    if self.inferior.is_none() {
                        println!("Error: no inferior");
                        return;
                    }
                    if let Err(_) = self
                        .inferior
                        .as_ref()
                        .unwrap()
                        .print_backtrace(&self.debug_data)
                    {
                        println!("Error: failed to print backtrace");
                    }
                }
                DebuggerCommand::Break(arg) => {
                    // parse the arg to get the addr
                    // valid arg includes *addr, func_name, line_number.
                    let addr;
                    if arg.starts_with('*') {
                        // the arg is an address.
                        if let Some(raw_addr) = parse_address(&arg[1..]) {
                            // validate address.
                            // the address is valid if it corresponds a valid line number.
                            if self.debug_data.get_line_from_addr(raw_addr).is_none() {
                                println!("Error: invalid breakpoint address");
                            }
                            addr = raw_addr;
                        } else {
                            println!("Error: failed to parse breakpoint address");
                            return;
                        }
                    } else if let Ok(line_number) = arg.parse::<usize>() {
                        if let Some(raw_addr) = self.debug_data.get_addr_for_line(None, line_number)
                        {
                            addr = raw_addr;
                        } else {
                            println!("Error: invalid breakpoint line number");
                            return;
                        }
                    } else if let Some(raw_addr) = self.debug_data.get_addr_for_function(None, &arg)
                    {
                        addr = raw_addr;
                    } else {
                        println!("Error: invalid breakpoint argument");
                        return;
                    }

                    // check if there exists a breakpoint.
                    if let Some(bp) = self.breakpoints.get(&addr) {
                        println!("{:#x} has an existing breakpoint {}", addr, bp.num);
                        return;
                    }

                    self.new_breakpoint(addr);
                }
                DebuggerCommand::Delete(arg) => {
                    if let Ok(bp_num) = arg.parse::<usize>() {
                        let mut exist = false;
                        for (&addr, bp) in self.breakpoints.iter() {
                            if bp.num == bp_num {
                                // delete the breakpoint with number bp_num.
                                self.delete_breakpoint(addr);
                                exist = true;
                                break;
                            }
                        }
                        if !exist {
                            println!("Error: no breakpoint with number {}", bp_num);
                            return;
                        }
                    } else {
                        println!("Error: failed to parse breakpoint number");
                    }
                }
                DebuggerCommand::Next => {}
                DebuggerCommand::Step => {}
                DebuggerCommand::Print(arg) => {}
                DebuggerCommand::Quit => {
                    if self.inferior.is_some() {
                        self.kill_inferior();
                    }
                    return;
                }
            }
        }
    }

    // set a new breakpoint at addr and maybe install it.
    fn new_breakpoint(&mut self, addr: usize) {
        // create a new breakpoint.
        let mut bp = Breakpoint {
            num: self.next_bp_num,
            addr,
            orig_byte: 0,
        };

        // set breakpoint is just a writing a record.
        // the breakpoint may not be installed immediately.
        println!("Set breakpoint {} at {:#x}", bp.num, bp.addr);

        // install this breakpoint immediately if the inferior is running.
        if self.inferior.is_some() {
            self.inferior.as_mut().unwrap().install_breakpoint(&mut bp);
        }

        // record this breakpoint for later usage, aka. to install it upon the
        // start of the inferior.
        self.breakpoints.insert(addr, bp);
        self.next_bp_num += 1;
    }

    // delete the breakpoint at address addr.
    fn delete_breakpoint(&mut self, addr: usize) {
        // remove the breakpoint record.
        if let Some(bp) = self.breakpoints.remove(&addr) {
            // restore the original byte at address addr.
            self.inferior.as_mut().unwrap().restore_orig_byte(&bp);
        } else {
            println!("Error: failed to delete breakpoint at address {:#x}", addr);
        }
    }

    /// This function prompts the user to enter a command, and continues re-prompting until the user
    /// enters a valid command. It uses DebuggerCommand::from_tokens to do the command parsing.
    ///
    /// You don't need to read, understand, or modify this function.
    fn get_next_command(&mut self) -> DebuggerCommand {
        loop {
            // Print prompt and get next line of user input
            match self.readline.readline("(deet) ") {
                Err(ReadlineError::Interrupted) => {
                    // User pressed ctrl+c. We're going to ignore it
                    println!("Type \"quit\" to exit");
                }
                Err(ReadlineError::Eof) => {
                    // User pressed ctrl+d, which is the equivalent of "quit" for our purposes
                    return DebuggerCommand::Quit;
                }
                Err(err) => {
                    panic!("Unexpected I/O error: {:?}", err);
                }
                Ok(line) => {
                    if line.trim().len() == 0 {
                        continue;
                    }
                    self.readline.add_history_entry(line.as_str());
                    if let Err(err) = self.readline.save_history(&self.history_path) {
                        println!(
                            "Warning: failed to save history file at {}: {}",
                            self.history_path, err
                        );
                    }
                    let tokens: Vec<&str> = line.split_whitespace().collect();
                    if let Some(cmd) = DebuggerCommand::from_tokens(&tokens) {
                        return cmd;
                    } else {
                        println!("Unrecognized command.");
                    }
                }
            }
        }
    }
}
