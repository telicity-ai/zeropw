//! Independent gpt-6-astra acceptance recheck at 897c9a6: actual empty/quoted envelopes.
mod notify_envelopes;

const ADDRESSES: [&str; 8] = [
    "sender@(nested(inner)).com",
    "sender@(nested(inner))",
    "sender@exa.(nested(inner)).com",
    "sender@exa.(nested(inner))",
    "sen(comment)der@example.com",
    "\"lo cal\"@(comment)example.com",
    "\"lo\\\\(cal\"@(comment)example.com",
    "Display <sender@(comment)example.com>",
];

#[test]
fn empty_and_quoted_comment_mailboxes_match_original_transport() {
    let mut pairs: Vec<(&str, &str)> = ADDRESSES
        .iter()
        .map(|a| (*a, "recipient@example.com"))
        .collect();
    pairs.extend(ADDRESSES.iter().map(|a| ("sender@example.com", *a)));
    notify_envelopes::check_envelopes(&pairs);
}
