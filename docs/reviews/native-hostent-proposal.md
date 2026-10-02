# Proposal: bounded native `hostent` access for SMTP hostname parity

Status: **proposal only**. This document does not approve an exception to
`rust/PORTING.md` §4 and does not add executable Rust. Implementation must wait
for explicit review and a user-approved, narrowly worded exception.

## Problem and required observable result

CPython 3.12.14 `socket.getfqdn()` calls `socket.gethostbyaddr()` and examines
the returned primary name followed by aliases, choosing the first name that
contains a dot. ZeroPW's safe Rust resolver currently loses `h_aliases` and on
macOS can miss the native NSS/DNS reverse answer entirely. This caused the
source-built macOS oracle to choose a reverse-resolved IPv6 name while Rust
sent `[192.168.64.4]` in SMTP EHLO/HELO.

The proposed seam is:

```rust
pub(crate) struct NativeHostent {
    pub primary: Vec<u8>,
    pub aliases: Vec<Vec<u8>>,
}

pub(crate) fn gethostbyaddr(addr: IpAddr)
    -> Result<Option<NativeHostent>, NativeHostentError>;
```

It returns owned bytes in native order. SMTP performs the CPython-compatible
name decoding and `getfqdn` selection after the FFI storage has been copied.
`None` means the native database reported no entry. `Err` means a resolver or
ABI failure; SMTP must preserve its current `getfqdn` fallback for lookup
failure rather than inventing a PTR name. The module never receives secrets
and must not log the address, hostname, aliases, `errno`, or resolver text.

## Primary-source basis

- The [CPython 3.12.14 socket implementation](https://github.com/python/cpython/blob/v3.12.14/Modules/socketmodule.c#L5778-L5790)
  is the behavior oracle. On Unix, `sock_decode_hostname` uses
  `PyUnicode_FromString` for `h_name`, and `gethost_common` uses the same
  function directly for every alias: both are strict UTF-8 decoding, not the
  filesystem encoding, locale encoding, or IDNA. A decoding failure makes
  `socket.gethostbyaddr` raise `UnicodeDecodeError`, a `ValueError` subclass,
  so `socket.getfqdn`'s `except socket.error` does not catch it. Therefore the
  SMTP caller behavior for invalid native UTF-8 must be pinned explicitly
  rather than treated as lookup miss.
  [CPython's `socket.getfqdn`](https://github.com/python/cpython/blob/v3.12.14/Lib/socket.py)
  prepends the primary name to the alias list and selects the first dotted
  value.
- The [GNU C Library host-name API](https://sourceware.org/glibc/manual/latest/html_node/Host-Names.html)
  specifies `gethostbyaddr_r`, address lengths/families, caller-owned result
  and scratch buffers, `result == NULL` for error/not-found, and `ERANGE`
  retry with a larger buffer. It labels the function MT-Safe subject to its
  documented `env locale` qualifications.
- Apple's archived [`gethostbyaddr(3)` manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/gethostent.3.html)
  documents the `hostent` layout, NULL failure, and static-storage overwrite
  caveat. It is old and therefore is treated as the conservative public ABI
  statement, not proof of modern thread-local lifetime.
- Apple's [macOS 15.0](https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-150)
  through [15.3](https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-153)
  distribution manifests pin Libinfo commit
  [`9fce29e`](https://github.com/apple-oss-distributions/Libinfo/tree/9fce29e5c5edc15d3ecea55116ca17d3f6350603)
  (`Libinfo-592`); [macOS 15.4](https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-154)
  pins `21013f6` (`Libinfo-595`), and
  [15.5](https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-155)/
  [15.6](https://github.com/apple-oss-distributions/distribution-macOS/tree/macos-156)
  pin `4eaf5bf` (`Libinfo-597`). The `libinfo.c` plus `thread_data.c` bytes
  relevant here are identical across those three commits (combined SHA-256
  `34b0d0a5bd5206946e9f4c5a74cbf615f3227f279eb2085adcf47ca3fe5c7853`).
  Those tagged sources implement
  [`gethostbyaddr`](https://github.com/apple-oss-distributions/Libinfo/blob/9fce29e5c5edc15d3ecea55116ca17d3f6350603/lookup.subproj/libinfo.c#L1247-L1268)
  by storing the returned item through `LI_set_thread_item(CATEGORY_HOST +
  200, item)` before returning its embedded `hostent`.
  [`thread_data.c`](https://github.com/apple-oss-distributions/Libinfo/blob/9fce29e5c5edc15d3ecea55116ca17d3f6350603/lookup.subproj/thread_data.c)
  creates the storage with `pthread_key_create`, obtains it with
  `pthread_getspecific`, and releases the previous item when the same keyed
  slot is replaced. Thus, for that source revision, another thread cannot
  overwrite this thread's result; the next same-thread lookup can.

## Proposed Linux implementation

The Linux branch calls only `libc::gethostbyaddr_r`:

```rust
let octets: [u8; 4] | [u8; 16] = addr.octets();
let (ptr, len, family) =
    (octets.as_ptr().cast(), octets.len() as socklen_t, AF_INET | AF_INET6);
let mut entry = MaybeUninit::<libc::hostent>::zeroed();
let mut result: *mut libc::hostent = null_mut();
let mut h_error = 0;
let mut scratch = vec![0_u8; 1024];
loop {
    let rc = unsafe {
        libc::gethostbyaddr_r(ptr, len, family, entry.as_mut_ptr(),
            scratch.as_mut_ptr().cast(), scratch.len(), &mut result, &mut h_error)
    };
    if rc == ERANGE { grow_with_checked_doubling_and_try_reserve(&mut scratch)?; continue; }
    if rc != 0 { return Err(NativeHostentError::Lookup); }
    if result.is_null() { return Ok(None); }
    return unsafe { copy_hostent(result) };
}
```

The actual implementation should avoid the illustrative union-like local
type above by using separate IPv4 and IPv6 arms, so the pointer always refers
to a live `[u8; 4]` or `[u8; 16]`. Length is exactly 4 for `AF_INET` and 16 for
`AF_INET6`; it is never `size_of(sockaddr_*)`. The scratch buffer remains live
through the complete copy. Growth has no arbitrary semantic cap: checked
doubling plus `try_reserve` maps integer/allocation failure to `Err`, preventing
wraparound or a dangling pointer. Each retry resets `result` and `h_error`.

On success, the code should additionally require `result == entry.as_mut_ptr()`
and validate `h_addrtype == family` and `h_length == len`; disagreement is an
ABI error. It does not dereference address-list entries because SMTP needs only
the primary name and aliases.

## Proposed macOS implementation

Darwin does not expose `gethostbyaddr_r`. The macOS branch calls
`libc::gethostbyaddr` with the same exact octet pointer, length, and family.
A process-global `Mutex<()>` owned by `native_hostent` serializes all calls made
through this module. While holding it, the function copies the complete primary
name and ordered alias list into Rust-owned buffers and invokes no user callback,
resolver API, logging API, or formatting code. Copying necessarily allocates.
The safety argument therefore assumes the repository's ordinary Rust/system
allocator does not call a host-database API; a user-installed global allocator
whose allocation callback re-enters `gethostbyaddr` would violate the contract
and deadlock or replace the same-thread slot. The eventual module must document
that assumption instead of claiming allocation-free copying. The guard is
released only after copying finishes.

The safety argument relies on the current Apple source's stronger thread-local
contract: the result is retained in the calling thread's `CATEGORY_HOST + 200`
slot until another lookup on that same thread replaces it. The mutex also
serializes this module's calls for defense in depth and for older static-storage
implementations. It cannot serialize unrelated third-party calls in the same
process; therefore approval must be conditional on the supported macOS libc
actually matching the cited thread-local implementation. If that cannot be
established for every supported deployment target, this design is not ready.

Darwin `NULL` maps directly to `Ok(None)`. SMTP's only consumer implements
`getfqdn`, which takes the same fallback for every `socket.gethostbyaddr` error;
it does not expose or branch on `h_errno`. Reading `h_errno` would add unsafe
thread-local/macro ABI surface without changing this consumer's behavior, so it
is deliberately excluded. No retry is invented on Darwin because CPython calls
the same non-reentrant API once.

## `hostent` copy invariants

The sole shared unsafe helper is conceptually:

```rust
unsafe fn copy_hostent(p: *const libc::hostent)
    -> Result<Option<NativeHostent>, NativeHostentError>
```

Its precondition is a non-NULL successful libc result whose storage remains
live under the platform rule above. It checks `p`, then `h_name`, before using
`CStr::from_ptr`. A NULL `h_name` is an ABI error. A NULL `h_aliases` means an
empty list. Otherwise it reads the NULL-terminated pointer array in order;
each pointer slot is loaded with `ptr::read_unaligned` (CPython 3.12.14
explicitly uses `memcpy` because `h_aliases` entries can be misaligned), and
each non-NULL entry is copied immediately with
`CStr::from_ptr(...).to_bytes()`.
No borrowed pointer escapes. The `hostent` ABI promises both the pointer-array
terminator and each C-string terminator; a broken libc/NSS module violating
that C contract cannot be made memory-safe by a wrapper because no lengths are
provided. This trust boundary must be stated in the eventual unsafe block's
`SAFETY` comment.

Interior NUL cannot appear in a C hostname. The SMTP adapter applies strict
UTF-8 to every copied value in native order. Invalid UTF-8 is not silently
lossy-decoded and is not a lookup miss: it maps to the closest handled error
only after an oracle test pins how the enclosing notify/send path observes
CPython's uncaught `UnicodeDecodeError` under PORTING.md §3.5.

## Exact tests required before implementation acceptance

1. Linux and macOS differential test against the pinned CPython 3.12.14:
   for controlled IPv4 and IPv6 fixtures, compare primary name, alias order,
   and final `socket.getfqdn`/SMTP `local_hostname` byte-for-byte.
2. The existing macOS source-build regression
   `smtp::hostname_tests::local_hostname_matches_smtplib` must pass on the
   machine that previously produced the IPv6 `ip6.arpa` reverse name. No
   hard-coded suffix or address shortcut is acceptable.
3. A controlled NSS fixture with primary name lacking a dot and a later dotted
   alias proves ordered alias preservation changes the selected FQDN exactly
   as Python does.
4. Not-found, temporary failure, and permanent failure probes confirm the same
   SMTP fallback as Python. Tests must assert no hostname/address appears in
   errors or captured logs.
5. Linux forces at least one `ERANGE` retry with a deliberately small initial
   buffer and compares the final owned result after the scratch buffer drops.
6. IPv4/IPv6 tests assert the FFI receives lengths 4/16 and families
   `AF_INET`/`AF_INET6`; malformed/unsupported family is unreachable from the
   typed `IpAddr` API.
7. macOS concurrency stress performs lookups from many threads while a second
   native test helper also calls libc directly. Returned primary/alias vectors
   must never cross-contaminate. Run under AddressSanitizer and ThreadSanitizer
   in a dedicated native CI job if those sanitizers support the resolver path.
8. A C fixture returning synthetic `hostent` layouts covers NULL result,
   NULL `h_name`, NULL `h_aliases`, empty aliases, multiple ordered aliases,
   and family/length mismatch without consulting live DNS.

## Proposed bounded §4 exception text

If and only if review accepts this design and the platform probes pass, add:

> `unsafe` is additionally permitted only inside
> `rust/src/native_hostent.rs`, only for calls to `gethostbyaddr_r` on
> Linux, `gethostbyaddr` on macOS, and immediate read-only copying of the
> returned `hostent` graph into owned Rust bytes. The unsafe code must use
> typed `IpAddr` octets with exact 4/16-byte lengths, validate all nullable
> top-level fields before dereference, retain the Linux scratch buffer for
> the copy, hold the documented macOS synchronization guard for the copy,
> return no borrowed pointer, and contain a `SAFETY` comment tied to the
> cited libc contracts. No other resolver FFI, global-variable mutation,
> or unsafe code is permitted by this exception.

This wording is intentionally narrower than allowing "network FFI" or
"libc resolver calls" generally.

## Outstanding uncertainties blocking approval

- Apple's public archived manual says static storage, while the pinned macOS
  15.0-15.6 Libinfo sources use thread-specific storage. Confirm the project's
  minimum/maximum supported macOS range; the source mapping above closes 15.x
  only and must not be generalized to older or future releases.
- Confirm whether any supported macOS 15 runtime path bypasses `LI_set_thread_item`, and
  whether resolver callbacks or cancellation can replace the same thread slot
  before `gethostbyaddr` returns. The inspected synchronous source does not.
- Confirm the enclosing ZeroPW notify error mapping for CPython's strict-UTF-8
  failure using a controlled native fixture. The decoding primitive itself is
  closed by the pinned CPython source above.
- NSS plugins are native trusted code. Their violation of the documented
  NULL-terminated `hostent` graph would invalidate `CStr`/pointer-array safety;
  decide whether the product's supported NSS set is the platform-provided set
  only.
- Live DNS is mutable. Acceptance needs controlled authoritative fixtures in
  addition to the real-machine regression, and must retain the old evidence
  rather than replacing it with a single passing lookup.
