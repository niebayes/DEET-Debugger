use crate::debugger_command::DebuggerCommand;
use crate::dwarf_data::{DwarfData, Error as DwarfError};
use crate::inferior::{Inferior, Status};
use nix::sys::ptrace;
use rustyline::error::ReadlineError;
use rustyline::Editor;

pub struct Debugger {
    target: String,
    history_path: String,
    readline: Editor<()>,
    inferior: Option<Inferior>,
    debug_data: DwarfData,
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
        }
    }

    pub fn cont_inferior(&mut self) {
        // run the inferior.
        let res = self.inferior.as_mut().unwrap().cont();
        let pid = self.inferior.as_ref().unwrap().pid();
        match res {
            Ok(Status::Stopped(signal, _)) => {
                println!("Child stopped (signal {:?})", signal);

                if let Ok(regs) = ptrace::getregs(pid) {
                    // print current stack frame.
                    let line = self.debug_data.get_line_from_addr(regs.rip as usize);
                    let func_name = self.debug_data.get_function_from_addr(regs.rip as usize);
                    if line.is_some() && func_name.is_some() {
                        println!(
                            "Stopped at {} ({}:{})",
                            func_name.as_ref().unwrap(),
                            line.as_ref().unwrap().file,
                            line.as_ref().unwrap().number
                        );
                    }
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
                        // resume the inferior.
                        self.cont_inferior();
                    } else {
                        println!("Error starting subprocess");
                    }
                }
                DebuggerCommand::Cont => {
                    if self.inferior.is_none() {
                        println!("Error no inferior");
                        return;
                    }
                    self.cont_inferior();
                }
                DebuggerCommand::Back => {
                    if self.inferior.is_none() {
                        println!("Error no inferior");
                        return;
                    }
                    if let Err(_) = self
                        .inferior
                        .as_ref()
                        .unwrap()
                        .print_backtrace(&self.debug_data)
                    {
                        println!("Error print backtrace");
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
