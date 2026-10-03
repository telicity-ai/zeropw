# Run-registry fixtures generated from the Python prototype

`credential_patterns.json` was recorded once on 2026-10-03 from the Python
prototype at commit 942a963 (CPython 3.12.14, Linux parity VM): for each
synthetic secret (base64), the full list of output-filter patterns that
`zeropw.runs.credential_patterns` derived (base64). It is the expected value
of `rust/tests/runs.rs::patterns_match_python_oracle_for_binary_and_alignment_cases`
and `rust/tests/runtime_parity_gaps.rs::credential_patterns_strip_like_bytes_strip`.

The secrets are the samples of those two tests: `b""`, `b"a"`,
`b" abc\t\n"`, `b"secret-value-123!"`, `bytes(range(256))`,
`b"\x0bsynthetic-secret\x0b"`, `b"\x0c\t synthetic-secret\r\n"`,
`b"\x1csynthetic-secret\x1c"`, `b"synthetic-secret"`.

Script (run from the repository root inside the VM:
`PYTHONPATH=$PWD python3.12 gen.py > credential_patterns.json`):

```python
import base64, json
from zeropw.runs import credential_patterns

samples = [b"", b"a", b" abc\t\n", b"secret-value-123!", bytes(range(256)),
           b"\x0bsynthetic-secret\x0b", b"\x0c\t synthetic-secret\r\n",
           b"\x1csynthetic-secret\x1c", b"synthetic-secret"]
cases = [{"secret": base64.b64encode(s).decode(),
          "patterns": [base64.b64encode(p).decode() for p in credential_patterns(s)]}
         for s in samples]
print(json.dumps({"cases": cases}, indent=1))
```

The values were captured by the former Python-oracle tests themselves (same
calls) and assembled into this file; the other expected values of
`runtime_parity_gaps.rs` (shebang run outcomes, `tools.request` header
outcomes, `tools._resolve_program` results) were recorded in the same run
and written into that test directly.
