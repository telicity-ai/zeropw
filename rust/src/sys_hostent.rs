//! CPython 3.12.14's `socket.gethostbyaddr` and `socket.gethostbyname`
//! (`Modules/socketmodule.c`: `socket_gethostbyaddr`,
//! `socket_gethostbyname`, `setipaddr`, `gethost_common`, `set_herror`,
//! `set_gaierror`).
//!
//! `smtplib` picks its EHLO name with `socket.getfqdn()`, which needs the
//! `hostent` alias list of a reverse lookup. No safe crate exposes that
//! list, so this module is the crate's second `unsafe` site (coordinator
//! ruling of 2026-10-03, rust/PORTING.md §4). Every `unsafe` block carries a
//! `// SAFETY:` comment, all data is copied out of the `hostent` before its
//! buffer (Linux) or the process-wide lock (macOS) is released, and no
//! pointer leaves this module: callers only see the safe functions below.
//!
//! Platform paths, as CPython selects them:
//! * Linux (`HAVE_GETHOSTBYNAME_R_6_ARG`): `gethostbyaddr_r` into an
//!   8-byte-aligned 16384-byte buffer passed as 16383 bytes.
//! * macOS (`USE_GETHOSTBYNAME_LOCK`): `gethostbyaddr` while holding a
//!   process-wide lock (`netdb_lock`), which is also held across
//!   `gethost_common`.
//!
//! In both cases a failed lookup is reported with the thread's `h_errno`
//! (not glibc's `h_errnop` out-parameter), exactly as `gethost_common` does.
#[cfg(target_os = "linux")]
use std::ffi::c_char;
use std::ffi::{CStr, CString, c_int};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dns_lookup::{AddrInfoHints, LookupError, LookupErrorKind, getaddrinfo};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("sys_hostent ports CPython's socket_gethostbyaddr for Linux and macOS only");

/// `(hostname, aliaslist, ipaddrlist)` as returned by `gethostbyaddr`.
pub(crate) type HostEnt = (String, Vec<String>, Vec<IpAddr>);

/// A Python exception these functions raise that carries no errno. An
/// `OSError` with an errno (`EAI_SYSTEM`, `EAFNOSUPPORT`) is a plain
/// `io::Error` with that raw OS error instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HostError {
    /// `UnicodeError` from the `idna` codec in the `et` argument conversion
    /// (or a host name that is not valid UTF-8, which `surrogateescape`
    /// turns into lone surrogates that the codec rejects).
    Unicode,
    /// `TypeError`: the encoded argument contains a NUL byte.
    NulByte,
    /// `UnicodeDecodeError`: `PyUnicode_FromString` of a `hostent` name or
    /// alias that is not valid UTF-8.
    UnicodeDecode,
    /// `socket.gaierror(code, gai_strerror(code))`.
    Gai(i32, String),
    /// `socket.herror(h_errno, hstrerror(h_errno))`.
    Herror(i32, String),
    /// `OSError(message)` without an errno.
    Os(&'static str),
}

impl HostError {
    /// `type(exc).__name__`.
    pub(crate) fn class(&self) -> &'static str {
        match self {
            HostError::Unicode => "UnicodeError",
            HostError::NulByte => "TypeError",
            HostError::UnicodeDecode => "UnicodeDecodeError",
            HostError::Gai(..) => "gaierror",
            HostError::Herror(..) => "herror",
            HostError::Os(_) => "OSError",
        }
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostError::Gai(code, message) | HostError::Herror(code, message) => {
                write!(f, "[Errno {code}] {message}")
            }
            HostError::Os(message) => f.write_str(message),
            other => f.write_str(other.class()),
        }
    }
}

impl std::error::Error for HostError {}

impl From<HostError> for io::Error {
    fn from(error: HostError) -> Self {
        io::Error::other(error)
    }
}

/// The [`HostError`] inside `error`, if it is one.
pub(crate) fn host_error(error: &io::Error) -> Option<&HostError> {
    error.get_ref()?.downcast_ref::<HostError>()
}

/// `type(exc).__name__` of the Python exception `error` stands for.
pub(crate) fn exception_class(error: &io::Error) -> &'static str {
    host_error(error).map_or_else(|| crate::pystr::os_error_class(error), HostError::class)
}

/// `isinstance(exc, OSError)`, i.e. what `except socket.error` catches.
pub(crate) fn is_os_error(error: &io::Error) -> bool {
    !matches!(
        host_error(error),
        Some(HostError::Unicode | HostError::NulByte | HostError::UnicodeDecode)
    )
}

/// `socket.gethostbyaddr(host)`.
pub(crate) fn gethostbyaddr(host: &str) -> io::Result<HostEnt> {
    let name = idna_argument(host)?;
    match setipaddr(&name, libc::AF_UNSPEC)? {
        IpAddr::V4(address) => lookup(&address.octets(), libc::AF_INET),
        IpAddr::V6(address) => lookup(&address.octets(), libc::AF_INET6),
    }
}

/// `socket.gethostbyname(host)`: `setipaddr(name, AF_INET)`.
pub(crate) fn gethostbyname(host: &str) -> io::Result<Ipv4Addr> {
    let name = idna_argument(host)?;
    match setipaddr(&name, libc::AF_INET)? {
        IpAddr::V4(address) => Ok(address),
        // An `AF_INET` hint never yields another family; CPython would
        // report the mismatch from `setipaddr`'s family switch.
        IpAddr::V6(_) => Err(HostError::Os("unknown address family").into()),
    }
}

/// `PyArg_ParseTuple(args, "et", "idna", &name)` for a `str` argument:
/// the `idna` codec, then the embedded-NUL check.
fn idna_argument(host: &str) -> io::Result<String> {
    let encoded = crate::pyidna::encode(host).map_err(|_| HostError::Unicode)?;
    if encoded.contains('\0') {
        return Err(HostError::NulByte.into());
    }
    Ok(encoded)
}

/// `setipaddr(state, name, addr_ret, sizeof, af)`.
fn setipaddr(name: &str, af: c_int) -> io::Result<IpAddr> {
    if name.is_empty() {
        let hints = AddrInfoHints {
            flags: libc::AI_PASSIVE,
            address: af,
            socktype: libc::SOCK_DGRAM,
            protocol: 0,
        };
        let mut results = getaddrinfo(None, Some("0"), Some(hints)).map_err(gai_error)?;
        let Some(Ok(first)) = results.next() else {
            return Err(HostError::Os("unsupported address family").into());
        };
        if results.next().is_some() {
            return Err(HostError::Os("wildcard resolved to multiple address").into());
        }
        return Ok(first.sockaddr.ip());
    }
    if name == "255.255.255.255" || name == "<broadcast>" {
        if af != libc::AF_INET && af != libc::AF_UNSPEC {
            return Err(HostError::Os("address family mismatched").into());
        }
        return Ok(IpAddr::V4(Ipv4Addr::BROADCAST));
    }
    // `idna_argument` rejected interior NULs, so this cannot fail.
    let c_name = CString::new(name).map_err(|_| HostError::NulByte)?;
    if (af == libc::AF_UNSPEC || af == libc::AF_INET)
        && let Some(address) = inet_pton4(&c_name)
    {
        return Ok(IpAddr::V4(address));
    }
    if (af == libc::AF_UNSPEC || af == libc::AF_INET6)
        && !name.contains('%')
        && let Some(address) = inet_pton6(&c_name)
    {
        return Ok(IpAddr::V6(address));
    }
    let hints = AddrInfoHints {
        address: af,
        ..AddrInfoHints::default()
    };
    let mut results = getaddrinfo(Some(name), None, Some(hints)).map_err(gai_error)?;
    match results.next() {
        Some(Ok(first)) => Ok(first.sockaddr.ip()),
        _ => Err(HostError::Os("unknown address family").into()),
    }
}

/// `set_gaierror`: `EAI_SYSTEM` is the errno's `OSError` (dns-lookup
/// captures `errno` right after the call); anything else is
/// `gaierror(code, gai_strerror(code))`.
fn gai_error(error: LookupError) -> io::Error {
    if matches!(error.kind(), LookupErrorKind::System) {
        return error.into();
    }
    let code = error.error_num();
    HostError::Gai(code, gai_strerror(code)).into()
}

#[allow(unsafe_code)]
fn gai_strerror(code: c_int) -> String {
    // SAFETY: `gai_strerror` accepts any code and returns a pointer to a
    // static, NUL-terminated message that is never freed or modified; it is
    // copied before returning.
    unsafe { CStr::from_ptr(libc::gai_strerror(code)) }
        .to_string_lossy()
        .into_owned()
}

#[allow(unsafe_code)]
fn hstrerror(code: c_int) -> String {
    // SAFETY: as for `gai_strerror`: `hstrerror` returns a static,
    // NUL-terminated message for any code, copied before returning.
    unsafe { CStr::from_ptr(libc::hstrerror(code)) }
        .to_string_lossy()
        .into_owned()
}

#[allow(unsafe_code)]
fn inet_pton4(name: &CStr) -> Option<Ipv4Addr> {
    let mut out = [0u8; 4];
    // SAFETY: `name` is NUL-terminated and outlives the call; for AF_INET
    // `inet_pton` writes at most `sizeof(struct in_addr)` = 4 bytes to
    // `out`, which is exactly that large and exclusively borrowed.
    let rc = unsafe { ffi::inet_pton(libc::AF_INET, name.as_ptr(), out.as_mut_ptr().cast()) };
    (rc > 0).then(|| Ipv4Addr::from(out))
}

#[allow(unsafe_code)]
fn inet_pton6(name: &CStr) -> Option<Ipv6Addr> {
    let mut out = [0u8; 16];
    // SAFETY: as in `inet_pton4`; for AF_INET6 `inet_pton` writes at most
    // `sizeof(struct in6_addr)` = 16 bytes.
    let rc = unsafe { ffi::inet_pton(libc::AF_INET6, name.as_ptr(), out.as_mut_ptr().cast()) };
    (rc > 0).then(|| Ipv6Addr::from(out))
}

/// Size of CPython's `char buf[16384] Py_ALIGNED(8)`.
#[cfg(target_os = "linux")]
const GETHOSTBY_BUF_SIZE: usize = 16384;

/// `gethostbyaddr_r(ap, al, af, &hp_allocated, buf, sizeof buf - 1, &h,
/// &errnop)` followed by `gethost_common`.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn lookup(address: &[u8], af: c_int) -> io::Result<HostEnt> {
    // `u64` elements give the buffer CPython's 8-byte alignment.
    let mut buf = vec![0u64; GETHOSTBY_BUF_SIZE / 8];
    let mut hostent = std::mem::MaybeUninit::<libc::hostent>::zeroed();
    let mut result: *mut libc::hostent = std::ptr::null_mut();
    let mut errnop: c_int = 0;
    let length = libc::socklen_t::try_from(address.len())
        .map_err(|_| HostError::Os("unsupported address family"))?;
    // SAFETY: `address` is readable for `length` bytes; `hostent`, `buf`
    // (16384 bytes, of which 16383 are offered, as CPython does), `result`
    // and `errnop` are live, exclusively borrowed locals that outlive the
    // call. `__h_errno_location` returns this thread's `h_errno` slot,
    // read immediately after the lookup on the same thread.
    let h_errno = unsafe {
        ffi::gethostbyaddr_r(
            address.as_ptr().cast(),
            length,
            af,
            hostent.as_mut_ptr(),
            buf.as_mut_ptr().cast::<c_char>(),
            GETHOSTBY_BUF_SIZE - 1,
            &mut result,
            &mut errnop,
        );
        *ffi::__h_errno_location()
    };
    // SAFETY: `result` is null or points at `hostent`, whose strings and
    // lists live in `buf`; both stay alive and unmodified until
    // `gethost_common` has copied everything out and returned.
    unsafe { gethost_common(result, h_errno, af) }
}

/// CPython's `netdb_lock` (`USE_GETHOSTBYNAME_LOCK`).
#[cfg(target_os = "macos")]
static NETDB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// `PyThread_acquire_lock(netdb_lock)`, `gethostbyaddr(ap, al, af)`,
/// `gethost_common`, then `PyThread_release_lock(netdb_lock)`.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn lookup(address: &[u8], af: c_int) -> io::Result<HostEnt> {
    let length = libc::socklen_t::try_from(address.len())
        .map_err(|_| HostError::Os("unsupported address family"))?;
    // The lock guards no data of its own, so a poisoned lock is still a
    // valid mutual-exclusion token.
    let _guard = NETDB_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // SAFETY: `address` is readable for `length` bytes for the duration of
    // the call. `h_errno` is libSystem's global, read right after the
    // lookup while `NETDB_LOCK` serialises every caller in this crate.
    let (h, h_errno) = unsafe {
        let h = ffi::gethostbyaddr(address.as_ptr().cast(), length, af);
        (h, ffi::h_errno)
    };
    // SAFETY: `h` is null or points at Libinfo's result storage, which the
    // next `gethostby*` call may overwrite; `NETDB_LOCK` is held until
    // `gethost_common` has copied everything out and returned.
    unsafe { gethost_common(h, h_errno, af) }
}

/// `gethost_common(state, h, addr, sizeof(addr), af)`.
///
/// # Safety
///
/// `h` must be null or point to a `hostent` whose name, alias list,
/// address list and the strings/addresses they reference stay valid and
/// unmodified for the duration of the call.
#[allow(unsafe_code)]
unsafe fn gethost_common(
    h: *const libc::hostent,
    h_errno: c_int,
    af: c_int,
) -> io::Result<HostEnt> {
    if h.is_null() {
        return Err(HostError::Herror(h_errno, hstrerror(h_errno)).into());
    }
    // SAFETY: non-null and valid per this function's contract.
    let h = unsafe { &*h };
    if h.h_addrtype != af {
        return Err(io::Error::from_raw_os_error(libc::EAFNOSUPPORT));
    }
    // SF #1511317: `h_aliases` can be NULL.
    let mut aliases = Vec::new();
    if !h.h_aliases.is_null() {
        let mut slot = h.h_aliases.cast_const();
        loop {
            // SAFETY: `slot` walks the NULL-terminated alias array of the
            // valid hostent and is read before it passes the terminator;
            // CPython reads it with `memcpy` because it may be misaligned.
            let alias = unsafe { slot.read_unaligned() };
            if alias.is_null() {
                break;
            }
            // SAFETY: each alias is a NUL-terminated string of the hostent.
            aliases.push(decode(unsafe { CStr::from_ptr(alias) })?);
            // SAFETY: the terminator has not been reached, so the next slot
            // is still inside the array.
            slot = unsafe { slot.add(1) };
        }
    }
    let mut addresses = Vec::new();
    // CPython dereferences `h_addr_list` unconditionally; glibc and
    // Libinfo always provide it, and a NULL list is read as empty rather
    // than crashing.
    if !h.h_addr_list.is_null() {
        let mut slot = h.h_addr_list.cast_const();
        loop {
            // SAFETY: as for the alias array.
            let entry = unsafe { slot.read_unaligned() };
            if entry.is_null() {
                break;
            }
            // CPython copies `sizeof(sin_addr)`/`sizeof(sin6_addr)` bytes
            // for the requested family (`h_addrtype == af` was checked).
            // SAFETY: each entry of an `af` hostent holds an address of
            // that family's length; unaligned reads copy it out.
            let address = if af == libc::AF_INET6 {
                IpAddr::V6(Ipv6Addr::from(unsafe {
                    entry.cast::<[u8; 16]>().read_unaligned()
                }))
            } else {
                IpAddr::V4(Ipv4Addr::from(unsafe {
                    entry.cast::<[u8; 4]>().read_unaligned()
                }))
            };
            addresses.push(address);
            // SAFETY: as for the alias array.
            slot = unsafe { slot.add(1) };
        }
    }
    if h.h_name.is_null() {
        // CPython would pass NULL to `PyUnicode_FromString` and crash; no
        // resolver returns a nameless entry, so fail closed instead.
        return Err(HostError::Os("gethostbyaddr returned no host name").into());
    }
    // SAFETY: `h_name` is a NUL-terminated string of the valid hostent.
    let name = decode(unsafe { CStr::from_ptr(h.h_name) })?;
    Ok((name, aliases, addresses))
}

/// `PyUnicode_FromString`: strict UTF-8, `UnicodeDecodeError` otherwise.
fn decode(text: &CStr) -> io::Result<String> {
    text.to_str()
        .map(str::to_owned)
        .map_err(|_| HostError::UnicodeDecode.into())
}

#[allow(unsafe_code)]
mod ffi {
    use std::ffi::{c_char, c_int, c_void};

    unsafe extern "C" {
        pub(super) fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;

        #[cfg(target_os = "linux")]
        pub(super) fn gethostbyaddr_r(
            addr: *const c_void,
            len: libc::socklen_t,
            type_: c_int,
            result_buf: *mut libc::hostent,
            buf: *mut c_char,
            buflen: libc::size_t,
            result: *mut *mut libc::hostent,
            h_errnop: *mut c_int,
        ) -> c_int;

        #[cfg(target_os = "linux")]
        pub(super) fn __h_errno_location() -> *mut c_int;

        #[cfg(target_os = "macos")]
        pub(super) fn gethostbyaddr(
            addr: *const c_void,
            len: libc::socklen_t,
            type_: c_int,
        ) -> *mut libc::hostent;

        /// `extern int h_errno;` in macOS `<netdb.h>`.
        #[cfg(target_os = "macos")]
        #[allow(non_upper_case_globals)]
        pub(super) static h_errno: c_int;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use serde_json::{Value, json};
    use std::io;

    use super::{HostError, exception_class, host_error};

    /// Inputs covering every `setipaddr` branch and `gethost_common`
    /// outcome reachable on the test host: the wildcard, broadcast and
    /// numeric short cuts, scoped IPv6, IDNA failures, an embedded NUL,
    /// names that do not resolve, addresses without a reverse entry,
    /// hosts-file entries with and without aliases, and this host's name.
    /// The `zpw-hostent-*` names and the 192.0.2.77/78, 2001:db8::77
    /// addresses resolve only where the test host's /etc/hosts has entries
    /// for them (dotted and undotted aliases, a non-UTF-8 alias); elsewhere
    /// both implementations fail identically.
    pub(crate) fn cases() -> Vec<String> {
        let mut cases: Vec<String> = [
            "",
            " ",
            "0.0.0.0",
            "::",
            "255.255.255.255",
            "<broadcast>",
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "localhost",
            "LOCALHOST",
            " localhost\t",
            "ip6-localhost",
            "ip6-loopback",
            "10.255.255.1",
            "01.2.3.4",
            "1.2.3",
            "::2",
            "fe80::1%lo",
            "nonexistent.invalid",
            "b\u{fc}cher.invalid",
            "a\0b",
            "192.0.2.77",
            "192.0.2.78",
            "2001:db8::77",
            "zpw-hostent-short",
            "zpw-hostent-alias.example",
            "zpw-hostent-v6",
            "zpw-hostent-badalias",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
        cases.push("x".repeat(64));
        cases.push(format!("{}.example", "y".repeat(63)));
        cases.push(
            rustix::system::uname()
                .nodename()
                .to_string_lossy()
                .into_owned(),
        );
        cases
    }

    /// An exception outcome, encoded as [`python_outcomes`] encodes it:
    /// the class name, plus `args` for an `OSError`.
    pub(crate) fn rust_error(error: &io::Error) -> Value {
        let args = match host_error(error) {
            Some(HostError::Gai(code, message) | HostError::Herror(code, message)) => {
                json!([code, message])
            }
            Some(HostError::Os(message)) => json!([message]),
            Some(_) => json!([]),
            None => json!([error.raw_os_error(), crate::pystr::os_error_strerror(error)]),
        };
        json!({"error": exception_class(error), "args": args})
    }

    /// `socket.<function>(case)` for every case in one Python thread:
    /// `{"ok": value}` or `{"error": class, "args": [...]}`.
    pub(crate) fn python_outcomes(function: &str, cases: &[String]) -> Vec<Value> {
        let cases = crate::pystr::repr_str(&serde_json::to_string(cases).unwrap());
        let script = format!(
            r#"
import json, socket
out = []
for case in json.loads({cases}):
    try:
        value = socket.{function}(case)
    except Exception as exc:
        args = list(exc.args) if isinstance(exc, OSError) else []
        out.append({{"error": type(exc).__name__, "args": args}})
    else:
        out.append({{"ok": value}})
print(json.dumps(out))
"#
        );
        serde_json::from_str(crate::oracle::python(&script).trim()).unwrap()
    }

    /// Runs `f` over the cases on one fresh thread, mirroring the single
    /// Python thread, so `h_errno` has the same history on both sides.
    /// Runs `compute` in a fresh copy of this test binary and returns its
    /// JSON result; returns `None` when this process IS that copy (after
    /// printing the result), so the caller must stop there.
    ///
    /// The resolver differentials need a process whose only lookups are the
    /// ones under test: on macOS, Libinfo orders `getaddrinfo` results by
    /// process-wide history (one `AI_PASSIVE` wildcard query makes later
    /// `localhost` lookups answer `::1` first, in CPython and here alike),
    /// and every other test thread's lookups would feed that history. The
    /// Python oracle likewise runs in a fresh process.
    pub(crate) fn fresh_process(test: &str, compute: impl FnOnce() -> Value) -> Option<Value> {
        const CHILD: &str = "ZEROPW_RESOLVER_TEST_CHILD";
        const MARK: &str = "ZEROPW_RESOLVER_TEST_RESULT=";
        if std::env::var(CHILD).as_deref() == Ok(test) {
            println!("{MARK}{}", compute());
            return None;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(CHILD, test)
            .output()
            .unwrap();
        // libtest's progress text may share the line, and where the child's
        // test output lands (stdout or stderr) is libtest's choice.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let line = stdout
            .lines()
            .chain(stderr.lines())
            .find_map(|line| line.split_once(MARK).map(|(_, rest)| rest))
            .unwrap_or_else(|| {
                panic!(
                    "child {test} printed no result ({}): {stdout}{stderr}",
                    output.status
                )
            });
        Some(serde_json::from_str(line).unwrap())
    }

    pub(crate) fn rust_outcomes(
        test: &str,
        cases: &[String],
        f: fn(&str) -> Value,
    ) -> Option<Vec<Value>> {
        let value = fresh_process(test, || {
            Value::Array(cases.iter().map(|case| f(case)).collect())
        })?;
        match value {
            Value::Array(values) => Some(values),
            other => panic!("unexpected child result {other}"),
        }
    }

    pub(crate) fn assert_parity(function: &str, cases: &[String], rust: &[Value]) {
        let python = python_outcomes(function, cases);
        assert_eq!(rust.len(), python.len());
        for ((case, rust), python) in cases.iter().zip(rust).zip(&python) {
            assert_eq!(rust, python, "socket.{function}({case:?}) differed");
        }
    }

    #[test]
    fn gethostbyaddr_matches_socketmodule() {
        let cases = cases();
        let Some(rust) = rust_outcomes(
            "sys_hostent::tests::gethostbyaddr_matches_socketmodule",
            &cases,
            |case| match super::gethostbyaddr(case) {
                Ok((name, aliases, addresses)) => {
                    let addresses: Vec<String> =
                        addresses.iter().map(ToString::to_string).collect();
                    json!({"ok": [name, aliases, addresses]})
                }
                Err(error) => rust_error(&error),
            },
        ) else {
            return;
        };
        assert_parity("gethostbyaddr", &cases, &rust);
    }

    #[test]
    fn gethostbyname_matches_socketmodule() {
        let cases = cases();
        let Some(rust) = rust_outcomes(
            "sys_hostent::tests::gethostbyname_matches_socketmodule",
            &cases,
            |case| match super::gethostbyname(case) {
                Ok(address) => json!({"ok": address.to_string()}),
                Err(error) => rust_error(&error),
            },
        ) else {
            return;
        };
        assert_parity("gethostbyname", &cases, &rust);
    }
}
