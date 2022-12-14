use crate::debugger::Breakpoint;
use crate::dwarf_data::DwarfData;
use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::mem::size_of;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;

pub enum Status {
    /// Indicates inferior stopped. Contains the signal that stopped the process, as well as the
    /// current instruction pointer that it is stopped at.
    Stopped(signal::Signal, usize),

    /// Indicates inferior exited normally. Contains the exit status code.
    Exited(i32),

    /// Indicates the inferior exited due to a signal. Contains the signal that killed the
    /// process.
    Signaled(signal::Signal),
}

/// This function calls ptrace with PTRACE_TRACEME to enable debugging on a process. You should use
/// pre_exec with Command to call this in the child process.
fn child_traceme() -> Result<(), std::io::Error> {
    ptrace::traceme().or(Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "ptrace TRACEME failed",
    )))
}

fn align_addr_to_word(addr: usize) -> usize {
    addr & (-(size_of::<usize>() as isize) as usize)
}

pub struct Inferior {
    child: Child,
}

// to debug a program, the debugger spawns an inferior process which further spawns a child process to
// load and execute the target program to be debugged.
// the inferior process acts like a container to wrap the process being debugged. It also acts like an
// interface to bridge the debugger and the process being debugged. It presents many function handles
// to be used by the debugger to manipulate the process being debugged.
// in summary, the debugger is the tracer and the inferior is the tracee.
impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>) -> Option<Inferior> {
        // create a new cmd for launching the target program.
        let mut cmd = Command::new(target);

        // when a process that has PTRACE_TRACEME enabled calls exec, the operating system will load
        // the specified program into the process, and then (before the new program starts running)
        // it will pause the process using SIGTRAP.
        unsafe {
            cmd.pre_exec(child_traceme);
        }

        // spawn a child process to execute the target program.
        let child = cmd.args(args).spawn().ok()?;

        let inf = Inferior { child };
        match inf.wait(None) {
            // ensure the child process is paused/stopped by the SIGTRAP signal.
            Ok(Status::Stopped(signal, _)) => {
                if signal != Signal::SIGTRAP {
                    return None;
                }
            }
            _ => {
                println!("Error: unexpected status returned from wait");
                return None;
            }
        }

        Some(inf)
    }

    pub fn cont(&mut self) -> Result<Status, nix::Error> {
        ptrace::cont(self.pid(), None)?;
        self.wait(None)
    }

    pub fn kill(&mut self) -> Result<Status, nix::Error> {
        // kill the child process and then reap it.
        if let Ok(_) = self.child.kill() {
            return self.wait(None);
        }
        Err(nix::Error::from_errno(nix::errno::Errno::EIO))
    }

    pub fn print_backtrace(&self, debug_data: &DwarfData) -> Result<(), nix::Error> {
        // In order to be useful, a backtrace should show function names and line numbers
        // so that a programmer can identify which parts of their program is running.
        // This is called "source-level debugging".
        // However, a running executable is comprised only of assembly instructions
        // and has no awareness of function names or line numbers.
        // In order to print such information, we need to read extra debugging symbols
        // that are stored within an executable compiled specifically for debugging.
        // This debugging information stores mappings between addresses and line numbers,
        // functions, variables, and more. With this information, we can find
        // where variables are stored in memory or figure out what line is being executed
        // based on the value of the processor???s instruction pointer.
        // On many platforms, debugging symbols are stored in a format called DWARF
        // and embedded inside the executable file.

        // The stack consists of stack frames, where each function???s local variables
        // are placed in its own stack frame. At the top of each stack frame is a return address,
        // which stores the address in the text segment where we should go to after returning
        // from this function.
        // When printing a backtrace, we do so using the return addresses.
        // First, we print the line number corresponding to %rip (where we are currently executing).
        // Then, we print the line number corresponding to the return address of our current stack frame.
        // Then, we print the line number for the return address of the previous stack frame, and so on,
        // until we reach the main function.

        let regs = ptrace::getregs(self.pid())?;
        let mut instruction_ptr = regs.rip as usize;
        let mut base_ptr = regs.rbp as usize;
        loop {
            // print current stack frame.
            let line = debug_data.get_line_from_addr(instruction_ptr);
            let func_name = debug_data.get_function_from_addr(instruction_ptr);
            if line.is_some() && func_name.is_some() {
                println!(
                    "{} ({}:{})",
                    func_name.as_ref().unwrap(),
                    line.as_ref().unwrap().file,
                    line.as_ref().unwrap().number
                );

                // if reaches the entry function main, stop backtracing.
                if func_name.as_ref().unwrap() == "main" {
                    break;
                }
            } else {
                // FIXME: what error to return?
                return Err(nix::Error::from_errno(nix::errno::Errno::EINVAL));
            }

            // proceed to the last stack frame.
            instruction_ptr =
                ptrace::read(self.pid(), (base_ptr + 8) as ptrace::AddressType)? as usize;
            base_ptr = ptrace::read(self.pid(), base_ptr as ptrace::AddressType)? as usize;
        }

        Ok(())
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        // Normally, SIGINT (triggered by Ctrl-C) will terminate a process,
        // but if a process is being traced under ptrace, SIGINT will cause it
        // to temporarily stop instead, as if it were sent SIGSTOP.
        // the same is true for all signals that typically terminate a process.
        // this is useful for debugging: if a program segfaults but is being traced
        // under ptrace, the program will stop instead of terminating so that you
        // can get a backtrace and inspect its memory.

        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                let regs = ptrace::getregs(self.pid())?;
                Status::Stopped(signal, regs.rip as usize)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }

    fn write_byte(&mut self, addr: usize, val: u8) -> Result<u8, nix::Error> {
        let aligned_addr = align_addr_to_word(addr);
        let byte_offset = addr - aligned_addr;
        let word = ptrace::read(self.pid(), aligned_addr as ptrace::AddressType)? as u64;
        let orig_byte = (word >> 8 * byte_offset) & 0xff;
        let masked_word = word & !(0xff << 8 * byte_offset);
        let updated_word = masked_word | ((val as u64) << 8 * byte_offset);
        ptrace::write(
            self.pid(),
            aligned_addr as ptrace::AddressType,
            updated_word as *mut std::ffi::c_void,
        )?;
        Ok(orig_byte as u8)
    }

    pub fn install_breakpoint(&mut self, bp: &mut Breakpoint) {
        if let Ok(orig_byte) = self.write_byte(bp.addr, 0xcc) {
            if bp.orig_byte == 0 {
                // it's the first time to install this breakpoint.
                bp.orig_byte = orig_byte;
            }
        } else {
            panic!("Failed to install breakpoint {} at {:#x}", bp.num, bp.addr);
        }
    }

    pub fn restore_orig_byte(&mut self, bp: &Breakpoint) {
        if let Ok(byte) = self.write_byte(bp.addr, bp.orig_byte) {
            assert_eq!(byte, 0xcc);
        } else {
            println!(
                "Failed to restore original byte {} for breakpoint {} at {:#x}",
                bp.orig_byte, bp.num, bp.addr
            );
        }
    }
}
