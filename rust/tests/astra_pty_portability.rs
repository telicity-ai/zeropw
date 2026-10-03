//! Controlled PTY launch semantics must not inherit a test runner's SIG_IGN
//! or blocked SIGINT mask: the keeper launches the prompt with default
//! interrupt handling even when it inherited an ignored or blocked SIGINT.
//! Original stimulus, deadlines and assertions remain.
mod cli_pty;

#[test]
fn prompt_abort_fixture_is_independent_of_runner_interrupt_disposition() {
    for inherited in [cli_pty::Inherited::Ignored, cli_pty::Inherited::Blocked] {
        cli_pty::check_admin_terminal_abort("interrupt", inherited);
    }
}
