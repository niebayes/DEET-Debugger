use std::collections::HashMap;

use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError, Location, Variable};
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
        // (b1) if the inferior terminates, clean and return.
        // (b2) if the address of the last executed instruction was set a breakpoint, reinstall the breakpoint.
        // (c) inferior::cont to resume the inferior to normal execution and wait.
        // (d1) if the inferior terminates, clean and return.
        // (d2) if the address of the last executed instruction was set a breakpoint, restore the original byte
        //      and rewind rip by one byte.

        // note, the step command will simply step the inferior by one instruction and reinstall the breakpoint if necessary.
        // it won't restore the original byte. The same goes for the next command which steps the inferior in a loop until it hits a breakpoint or the line
        // number changes. After its termination, the original byte is not restored however.
        // in summary, inorder to cooperate with the next and step commands, this function needs the following
        // modifications.
        // (before-a) if the address of the instruction to be executed was set a breakpoint, restore the original byte.

        // self.step() does the (before-a), (a), (b1), (b2) steps.
        if let Err(_) = self.step() {
            return;
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
                let pid = self.inferior.as_ref().unwrap().pid();
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
                    if self.inferior.is_none() {
                        println!("Error: no inferior");
                        return;
                    }

                    // this command triggers the following procedures:
                    // (a) record the line number of the instruction to be executed.
                    // (b) repeatedly call self.step to step one instruction forward until we hit
                    //     another line with a different line number.
                    // note, hitting a breakpoint won't interfere this command.
                    // if the inferior does not terminate, this command always step the
                    // inferior one line further.

                    let line_number = self.get_curr_line_number();
                    while let Ok(_) = self.step() {
                        if self.get_curr_line_number() != line_number {
                            break;
                        }
                    }
                }
                DebuggerCommand::Step => {
                    if self.inferior.is_none() {
                        println!("Error: no inferior");
                        return;
                    }

                    // this command triggers the following procedures:
                    // (a) if the address of the instruction to be executed was set a breakpoint, restore the original byte.
                    // (b) ptrace::step to step the inferior and wait.
                    // (c1) if the inferior terminates, clean and return.
                    // (c2) if the the address of the last executed instruction was set a breakpoint, reinstall the breakpoint.
                    if let Err(_) = self.step() {}
                }
                DebuggerCommand::Print(arg) => {
                    println!("Error: not implemented");
                    return;

                    if self.inferior.is_none() {
                        println!("Error: no inferior");
                        return;
                    }

                    if let Some(val) = self.get_var(&arg) {
                        println!("Variable {} = {}", &arg, val);
                    } else {
                        println!("Error: unknown variable name {}", &arg);
                    }
                }
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

    // step the inferior by one instruction and wait.
    fn step(&mut self) -> Result<(), ()> {
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
                    return Err(());
                }

                let last_exec_addr = instruction_ptr - 1;
                if let Some(bp) = self.breakpoints.get_mut(&last_exec_addr) {
                    self.inferior.as_mut().unwrap().install_breakpoint(bp);
                }
                Ok(())
            }
            Ok(Status::Exited(status)) => {
                println!("Child exited (status {})", status);
                self.clean();
                Err(())
            }
            Ok(Status::Signaled(signal)) => {
                println!("signaled by signal {}", signal);
                Ok(())
            }
            _ => {
                println!("Error: unexpected return status from wait");
                self.clean();
                Err(())
            }
        }
    }

    fn get_curr_line_number(&self) -> usize {
        let pid = self.inferior.as_ref().unwrap().pid();
        let regs = ptrace::getregs(pid).expect("error getregs");
        let exec_addr = regs.rip as usize - 1;
        self.debug_data
            .get_line_from_addr(exec_addr)
            .expect("error get_line_from_addr")
            .number
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

    // rewind the instruction pointer by one byte.
    fn rewind_rip(&mut self) {
        let pid = self.inferior.as_ref().unwrap().pid();
        // rewind/backoff the instruction pointer, i.e. make it holds the address of the
        // restored original byte, which one byte before the current instruction pointer, aka. rip.
        let mut regs = ptrace::getregs(pid).expect("error getregs");
        regs.rip -= 1;
        ptrace::setregs(pid, regs).expect("error setregs");
    }

    // FIXME: Shall I collect all vars upon start running an inferior?
    // FIXME: Does the dwarf data change over time as the inferior makes progress?
    // collect all variables from dwarf data
    // into a hash map with keys variable names and values Variables.
    fn collect_vars(&self) -> HashMap<&str, &Variable> {
        let mut var_val = HashMap::new();
        let files = &self.debug_data.files;
        for file in files.iter() {
            // collect global variables.
            for var in file.global_variables.iter() {
                var_val.insert(var.name.as_str(), var);
            }
            // collect local variables in each function.
            // FIXME: Does dwarf data format distinguishes local variables from different functions?
            for func in file.functions.iter() {
                for var in func.variables.iter() {
                    var_val.insert(var.name.as_str(), var);
                }
            }
        }

        var_val
    }

    fn get_var(&self, var_name: &str) -> Option<&str> {
        let pid = self.inferior.as_ref().unwrap().pid();
        let var_val = self.collect_vars();
        if let Some(&var) = var_val.get(var_name) {
            if let Location::Address(addr) = var.location {
                // TODO: implement this logic and test it.
                let mut buf = Vec::new();
                for i in 0..var.entity_type.size {
                    let word = ptrace::read(pid, (addr + i) as ptrace::AddressType).unwrap() as u8;
                    buf.push(word);
                }
                // aggregate all words in buf and cast it to a type with name var.entity_type.name.
                // that's the value for the variable with name var_name, return it in the &str representation.
            }
        }

        None
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
