# English notification contract

These fixed expectations translate the incident-email presentation into English.
Incident documents, timestamps, identities, counts, targets, rotation steps and
recovery actions are preserved from the corresponding historical Python cases.
The original files under `fixtures/python/response/` are unchanged.

Expected subjects/bodies were authored by translating those fixed cases, not by
running the current Rust renderer. Tests compare the full output and retain
credential-leakage assertions. This is an intentional presentation change, not
a claim of byte compatibility with the historical Korean emails.

`smtp_sessions.json` preserves the original 42 transport scenarios, outcomes and
audit records while replacing only the test-message MIME bytes and resulting
SMTP SIZE values. `generate-smtp-expectations.py` uses CPython 3.12.14 standard
email serialization independently of the Rust implementation, with no network
or product backend. Unicode address/header inputs remain intentional test data.
