//! Independent gpt-6-astra check of the fix's own claimed Python mailbox corpus.
mod notify_envelopes;

#[test]
fn comment_inside_domain_preserves_original_transport_envelope() {
    notify_envelopes::check_envelopes(&[
        ("sender@exa(comment)mple.com", "recipient@example.com"),
        ("sender@example.com", "recipient@exa(comment)mple.com"),
        (
            "sender@(comment)example.com",
            "recipient@(comment)example.com",
        ),
    ]);
}
