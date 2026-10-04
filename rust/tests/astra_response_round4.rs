//! Independent gpt-6-astra response fix review at 584ac71.
//! Synthetic state, actual native notify CLI, loopback SMTP; the expected
//! outcomes are the ones the original Python prototype reported.
mod notify_envelopes;

use notify_envelopes::{Receiver, notify_test, receiver, state};
use serde_json::json;

/// The receiver refuses any envelope other than the bare mailboxes; the
/// original delivered every one of these configured forms.
#[test]
fn supported_comments_inside_mailbox_match_python() {
    let state = state();
    for (sender, recipient) in [
        ("sender(Internal)@example.com", "recipient@example.com"),
        ("sender@(Internal)example.com", "recipient@example.com"),
        ("sender@example.com", "recipient(Internal)@example.com"),
        ("sender@example.com", "recipient@(Internal)example.com"),
        (
            "(Nested (inner)) sender@example.com",
            "recipient@example.com",
        ),
        (
            "sender@example.com(Nested (inner))",
            "recipient@example.com",
        ),
    ] {
        let (port, worker) = receiver(Receiver {
            enforce: true,
            data_timeout: false,
        });
        let result = notify_test(&state, port, sender, recipient, 1.0);
        let commands = worker.join().unwrap();
        assert_eq!(
            result,
            json!({"status": "sent"}),
            "{sender:?} -> {recipient:?}: {commands:?}"
        );
    }
}

#[test]
fn smtp_data_reply_timeout_matches_original_error_identity() {
    let state = state();
    let (port, worker) = receiver(Receiver {
        enforce: true,
        data_timeout: true,
    });
    let result = notify_test(
        &state,
        port,
        "sender@example.com",
        "recipient@example.com",
        0.05,
    );
    worker.join().unwrap();
    assert_eq!(
        result,
        json!({"status": "failed", "error": "SMTPServerDisconnected"})
    );
}
