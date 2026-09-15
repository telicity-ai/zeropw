"""Server-less team sync (docs/team-sync.md): device identity, DEK envelopes,
signed commits, and deterministic folding into an environment document.

Stage 1 only (docs/team-sync.md section 13, "단계 1"): keys, envelope, commits,
fold.  No networking; ``zeropw/team/transport.py`` and ``sync.py`` are later
stages.
"""

from __future__ import annotations
