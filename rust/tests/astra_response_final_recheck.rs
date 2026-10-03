//! Independent gpt-6-astra recheck at 55f95de: local/domain comment boundaries.
mod notify_envelopes;

const ADDRESSES: [&str; 7] = [
    "sen(comment)der@example.com",
    "sender(comment).foo@example.com",
    "sender.(comment)foo@example.com",
    "sender@exa(comment).com",
    "sender@exa.(comment)com",
    "sender(comment)@example.com",
    "sender@(comment)example.com",
];

#[test]
fn local_and_domain_comment_boundaries_preserve_transport_envelopes() {
    let mut pairs: Vec<(&str, &str)> = ADDRESSES
        .iter()
        .map(|a| (*a, "recipient@example.com"))
        .collect();
    pairs.extend(ADDRESSES.iter().map(|a| ("sender@example.com", *a)));
    notify_envelopes::check_envelopes(&pairs);
}
