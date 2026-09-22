# Astra team round 4 — supplemental completion

- Actual reviewer model: `gpt-6-astra`.
- Supplement tested at `b7e9c58`; final observed HEAD `9bc858ef588a61076809f69a4f96ceb605e85b6a` changes only response review/test evidence. Product source is unchanged between these commits.
- Team source remains identical to initial round-four checkout `a6e3e9e0babb0e4c59c529a8e5c6677617b70a10`; complete runtime product at the supplemental run is `318386de404ccbff4cdd8c3e0a79dbb1a4aa25e0`.

The coordinator identified the earlier write failure as a full disk and restored capacity by cleaning completed worker build artifacts. A read-only capacity check now shows 9.4 GiB available. Repeating the ordinary patch operation succeeded; no alternate write mechanism or safeguard bypass was used. The historical partial report `astra-team-round4.md` is preserved unchanged.

## New independent evidence

`cargo test --offline --test astra_team_round4 -- --test-threads=1`: **2 passed**, 22.43s, no ignored or filtered cases. All state, passphrases and endpoint names are synthetic.

`cargo clippy --offline --test astra_team_round4 -- -D warnings`: passed, 0.10s.

1. `original_user_role_self_removal_is_authored_and_propagated`: joins with the actual `user` role and explicitly verifies that role; admin-only disable publication is denied; the same user successfully authors its own removal; the owner's live authenticated peer receives it and removes that user while retaining the owner. This supplies the original assertion omitted by the admin-only AR3 mapping.
2. `original_local_mutual_removal_rotates_only_before_author_is_removed`: joins two actual admins, stops synchronization, calls local `membership::remove_member(..., None)` for the first removal and observes `dek_rotated=true`. Copies that exact signed fact to the second admin's ledger, invokes the local removal API in the reverse direction, observes `dek_rotated=false`, and verifies the final folded membership excludes both admins but retains the owner. This supplies the local API/rotation assertions omitted by the injected-fact AR3 mapping.

These are additional evidence for the two existing map rows; the original mapping file and prior tests have not been rewritten.

## Bounded verdict

No new product finding in this team review. ASTRA-TEAM-T1/P2, T2/P2, T3/P2, T4/P3 and T5/P2 remain resolved on their unchanged regressions. The two precise mapping gaps recorded in the partial report are now closed by actual independent tests. Together with the prior 102 passing native checks and the passing original three-process team lifecycle, the mapped original team behaviors are accepted within this measured scope, with the two explicitly documented constructor-call-shape differences retained.

This does not claim literal reproduction of every Python fixture topology or every auxiliary assertion, universal network/security correctness, Linux execution, or final integrated whole-product acceptance. The earlier report's descriptions of thread-hosted live runtime tests, nonempty independent raw TCP capture, and separate native multi-process E2E remain the precise evidence boundary. The interrupted round-three review remains historical partial evidence; its eight corrected tests were independently rerun in round four.
