use nix::sys::ptrace;
use nix::sys::signal;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
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

pub struct Inferior {
    child: Child,
}

impl Inferior {
    /// Attempts to start a new inferior process. Returns Some(Inferior) if successful, or None if
    /// an error is encountered.
    pub fn new(target: &str, args: &Vec<String>) -> Option<Inferior> {
        if args.len() < 1 {
            return None;
        }

        // create a new cmd for launching the target program.
        let mut cmd = Command::new(target);

        // before executing the target program, let the child process executes the child_traceme function.
        // when a process that has PTRACE_TRACEME enabled calls exec, the operating system will load
        // the specified program into the process, and then (before the new program starts running)
        // it will pause the process using SIGTRAP.
        // SIGTRAP signal is used exclusively by debuggers.
        unsafe {
            cmd.pre_exec(child_traceme);
        }

        // spawn a child process to execute the target program.
        let child = cmd
            .args(args)
            .spawn()
            .expect(&format!("failed to spawn {}", target));
        
        let inf = Inferior { child };
        let res = inf.wait(Some(WaitPidFlag::WUNTRACED));
        // ensure the child process is paused/stopped by the SIGTRAP signal.
        match res {
            Ok(Status::Stopped(signal, _)) => {
                if signal != Signal::SIGTRAP {
                    return None;
                }
            }
            _ => {
                println!("shall stopped on SIGTRAP");
                return None;
            }
        }

        Some(inf)
    }

    pub fn cont(&mut self) -> Result<Status, nix::Error> {
        if let Err(_) = ptrace::cont(self.pid(), None) {
            // FIXME: what nix::Error to return
            return Err(nix::Error::from_errno(nix::errno::Errno::ESRCH));
        }
        self.wait(None)
    }

    /// Returns the pid of this inferior.
    pub fn pid(&self) -> Pid {
        nix::unistd::Pid::from_raw(self.child.id() as i32)
    }

    /// Calls waitpid on this inferior and returns a Status to indicate the state of the process
    /// after the waitpid call.
    pub fn wait(&self, options: Option<WaitPidFlag>) -> Result<Status, nix::Error> {
        Ok(match waitpid(self.pid(), options)? {
            WaitStatus::Exited(_pid, exit_code) => Status::Exited(exit_code),
            WaitStatus::Signaled(_pid, signal, _core_dumped) => Status::Signaled(signal),
            WaitStatus::Stopped(_pid, signal) => {
                // let regs = ptrace::getregs(self.pid())?;
                // Status::Stopped(signal, regs.rip as usize)
                Status::Stopped(signal, 0)
            }
            other => panic!("waitpid returned unexpected status: {:?}", other),
        })
    }
}
