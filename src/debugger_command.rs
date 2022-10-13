pub enum DebuggerCommand {
    Quit,             // quit the debugger.
    Run(Vec<String>), // run the target program with args.
    Cont,             // resume the stopped target program.
    Back,             // print the stack backtrace.
    Break(String),    // set a breakpoint at addr or function name or line number.
    Delete(String),   // delete a breakpoint with the given breakpoint number.
    Next,             // step to the next line of source code and then stop.
    Step,             // step to the next instruction and then stop.
    Print(String),    // print the content of the given variable.
}

impl DebuggerCommand {
    pub fn from_tokens(tokens: &Vec<&str>) -> Option<DebuggerCommand> {
        match tokens[0] {
            "q" | "quit" => Some(DebuggerCommand::Quit),
            "r" | "run" => {
                let args = tokens[1..].to_vec();
                Some(DebuggerCommand::Run(
                    args.iter().map(|s| s.to_string()).collect(),
                ))
            }
            "c" | "cont" | "continue" => Some(DebuggerCommand::Cont),
            "back" | "backtrace" => Some(DebuggerCommand::Back),
            "b" | "break" => {
                if tokens.len() != 2 {
                    println!("Usage: {} <*addr> | <func_name> | <line_number>", tokens[0]);
                    None
                } else {
                    Some(DebuggerCommand::Break(tokens[1].to_string()))
                }
            }
            "d" | "delete" => {
                if tokens.len() != 2 {
                    println!("Usage: {} <breakpoint_number>", tokens[0]);
                    None
                } else {
                    Some(DebuggerCommand::Delete(tokens[1].to_string()))
                }
            }
            "n" | "next" => Some(DebuggerCommand::Next),
            "s" | "step" => Some(DebuggerCommand::Step),
            "p" | "print" => {
                if tokens.len() != 2 {
                    println!("Usage: {} <variable_name>", tokens[0]);
                    None
                } else {
                    Some(DebuggerCommand::Print(tokens[1].to_string()))
                }
            }
            // Default case:
            _ => None,
        }
    }
}
