# English notification contract

These fixed expectations translate the incident-email presentation into English.
Incident documents, timestamps, identities, counts, targets, rotation steps and
recovery actions are preserved from the corresponding historical Python cases.
The original files under `fixtures/python/response/` are unchanged.

Expected subjects/bodies were authored by translating those fixed cases, not by
running the current Rust renderer. Tests compare the full output and retain
credential-leakage assertions. This is an intentional presentation change, not
a claim of byte compatibility with the historical Korean emails.
