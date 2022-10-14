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

    pub fn cont_inferior(&mut self) {
        // note, when this function is called, the inferior is guaranteed to be in the
        // stopped state.
        // there're two possible causes:
        // (1) the inferior hits a breakpoint and stops after executing the 0xcc instruction.
        //     Now, rip holds the address of the instruction next to the 0xcc instruction.
        // (2) the inferior is signaled by, for e.g. SIGSTOP, issued from ctrl-c.
        //     Now, rip holds the address of the instruction to be executed next.
        // if it's the case (1), we need to restore the original byte replaced by the 0xcc instruction
        // and rewind the rip by one byte, so that the inferior continues from the original byte.
        // if otherwise it's the case (2), we simply resumes the inferior.
        // however, since it's guaranteed to have restored the original byte each time we hitted a
        // breakpoint, there's no need to take special handling for the case (1).
        // in summary, this function takes these steps:
        // (a) ptrace::step to step the inferior and wait.
        // (b1) if the inferior terminates, return.
        // (b2) if the address of the last executed instruction was set a breakpoint, reinstall the breakpoint.
        // (c) inferior::cont to resume the inferior to normal execution and wait.
        // (d1) if the inferior terminates, return.
        // (d2) if the address of the last executed instruction was set a breakpoint, restore the original byte
        //      and rewind rip by one byte.

        // note, the step command will simply step the inferior by one instruction and reinstall the breakpoint if necessary.
        // it won't restore the original byte. The same goes for the next command which steps the inferior in a loop until it hits a breakpoint or the line
        // number changes. After its termination, the original byte is not restored however.
        // in summary, inorder to cooperate with the next and step commands, this function needs the following
        // modifications.
        // (before-a) if the address of the instruction to be executed was set a breakpoint, restore the original byte.

        let pid = self.inferior.as_ref().unwrap().pid();
        let regs = ptrace::getregs(pid).expect("error getregs");
        let exec_addr = regs.rip as usize;
        if let Some(bp) = self.breakpoints.get(&exec_addr) {
            self.inferior.as_mut().unwrap().restore_orig_byte(bp);
        }

        ptrace::step(pid, Signal::SIGTRAP).expect("error step");
        match self.inferior.as_mut().unwrap().wait(None) {
            Ok(Status::Stopped(signal, instruction_ptr)) => {
                if signal != Signal::SIGTRAP {
                    println!("Error: inferior stopped by unexpected signal {}", signal);
                    self.clean();
                    return;
                }

                let last_exec_addr = instruction_ptr - 1;
                if let Some(bp) = self.breakpoints.get_mut(&last_exec_addr) {
                    self.inferior.as_mut().unwrap().install_breakpoint(bp);
                }
            }
            Ok(Status::Exited(status)) => {
                println!("Child exited (status {})", status);
                self.clean();
                return;
            }
            _ => {
                println!("Error: unexpected return status from wait");
                self.clean();
                return;
            }
        }

        match self.inferior.as_mut().unwrap().cont() {
            Ok(Status::Stopped(signal, instruction_ptr)) => {
                let last_exec_addr = instruction_ptr - 1;
                if let Some(bp) = self.breakpoints.get(&last_exec_addr) {
                    self.inferior.as_mut().unwrap().restore_orig_byte(bp);
                    self.rewind_rip();
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
                    // FIXME: correct the docker shared path.
                    // print the source code corresponding to current line.
                    // print_source_line(
                    //     line.as_ref().unwrap().file.as_str(),
                    //     line.as_ref().unwrap().number,
                    // );
                }
            }
            Ok(Status::Exited(status)) => {
                println!("Child exited (status {})", status);
                self.clean();
            }
            _ => {
                println!("Error: unexpected return status from wait");
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
                DebuggerCommand::Next => {
                    // this command only functions when the inferior is in the stopped state.
                    if self.inferior.is_none() {
                        println!("Error: no inferior");
                        return;
                    }

                    // note, this command resumes the execution of the inferior until it hits
                    // a different line. We cannot simply set a breakpoint at the next line,
                    // since, for e.g. we are in a loop, the next line in the source code may not
                    // be the next line of execution.
                    // therefore, we have to resume the execution step by step until the line number changes.

                    let pid = self.inferior.as_ref().unwrap().pid();
                    let regs = ptrace::getregs(pid).expect("error getregs");
                    // note, instruction pointer register holds the address of the next instruction,
                    // if the inferior is stopped by a breakpoint, then the next instruction is actually
                    // the replaced original byte, so we have to calculate the line number from that byte.
                    // if the inferior is stopped by, for e.g., ctrl-c, then we calculate the line number
                    // from the next instruction whose address is stored in the instruction pointer.
                    let mut addr = if self.breakpoints.contains_key(&(regs.rip as usize - 1)) {
                        regs.rip as usize - 1;
                    } else {
                        regs.rip
                    };
                    // the line number of the line we're currently in.
                    if let Some(line) = self.debug_data.get_line_from_addr(addr) {
                        // loop until the the execution hits a different line.
                        loop {
                            // if stopped by a breakpoint, the original byte is guaranteed to be already restored,
                            // so we can safely step the inferior.
                            ptrace::step(pid, Signal::SIGTRAP).expect("error step");
                            // wait for the inferior to stop.
                            let res = self.inferior.as_mut().unwrap().wait(None);
                            let mut hit_breakpoint = false;
                            match res {
                                Ok(Status::Stopped(signal, _)) => {
                                    if signal == Signal::SIGTRAP {
                                        // if a breakpoint was set at the address of the just stepped instruction,
                                        // we need to reinstall it.
                                        let regs = ptrace::getregs(pid).expect("error getregs");
                                        if let Some(bp) =
                                            self.breakpoints.get_mut(&(regs.rip as usize - 1))
                                        {
                                            // reinstall the breakpoint.
                                            self.inferior.as_mut().unwrap().install_breakpoint(bp);
                                        } else {
                                            // check if we've hit a breakpoint.
                                            if let Some(bp) = self.breakpoints.get(&(regs.rip)) {
                                                println!(
                                                    "Hit breakpoint {} at {:#x}",
                                                    bp.num, bp.addr
                                                );
                                                hit_breakpoint = true;
                                            }
                                        }
                                    } else {
                                        println!(
                                            "Error: inferiror stepped but interrupted by signal {}",
                                            signal
                                        );
                                        return;
                                    }
                                }
                                Ok(Status::Exited(_)) => {
                                    self.clean();
                                    println!("Child exited (status 0)");
                                    return;
                                }
                                _ => {
                                    println!("process {} encounters error on cont", pid);
                                    return;
                                }
                            }

                            // hitting a breakpoint also breaks the loop.
                            if hit_breakpoint {
                                break;
                            }

                            // check if the line number is changed.
                            let regs = ptrace::getregs(pid).expect("error getregs");
                            // if the next instruction is at a different line, break the loop.
                            // note, cannot offset -1 since we need the address of the next instruction.
                            addr = regs.rip;
                            if let Some(curr_line) = self.debug_data.get_line_from_addr(addr) {
                                if curr_line.number != line.number {
                                    break;
                                }
                            } else {
                                println!("Error: failed to get line from address {:#x}", addr);
                            }
                        }
                    } else {
                        println!("Error: failed to get line from address {:#x}", addr);
                    }
                }
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

    // set a new breakpoint at address addr and maybe install it.
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

    // clean the inferior and remove all breakpoints.
    fn clean(&mut self) {
        if self.inferior.is_some() {
            match self.inferior.as_mut().unwrap().wait(None) {
                Ok(Status::Stopped(_, _)) => self.kill_inferior(),
                _ => {}
            }
            // TODO: fix ugly code.
            if self.inferior.is_some() {
                drop(self.inferior.as_mut().unwrap());
                self.inferior = None;
            }
        }

        self.breakpoints.clear();
        self.next_bp_num = 0;
    }

    fn rewind_rip(&mut self) {
        let pid = self.inferior.as_ref().unwrap().pid();
        // rewind/backoff the instruction pointer, i.e. make it holds the address of the
        // restored original byte, which one byte before the current instruction pointer, aka. rip.
        let mut regs = ptrace::getregs(pid).expect("error getregs");
        regs.rip -= 1;
        ptrace::setregs(pid, regs).expect("error setregs");
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
