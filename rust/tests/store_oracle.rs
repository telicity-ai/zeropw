//! `zeropw::store::iso`: the `YYYY-MM-DDTHH:MM:SSZ` timestamp every
//! persisted document and audit line carries. The expected strings below are
//! the ones the Python prototype's `store.iso` (`time.strftime(...,
//! time.gmtime(ts))`) produced for the same inputs; timestamps far outside
//! any real clock are outside the compatibility contract (PORTING.md §0) and
//! only have to fail closed where `try_iso` refuses them.

use zeropw::store::iso;

#[test]
fn iso_formats_a_timestamp_table() {
    let cases: &[(f64, &str)] = &[
        (0.0, "1970-01-01T00:00:00Z"),                // epoch
        (-1.0, "1969-12-31T23:59:59Z"),               // one second before the epoch
        (-86400.0, "1969-12-31T00:00:00Z"),           // one day before the epoch
        (1.5, "1970-01-01T00:00:01Z"),                // fractional (floors, not rounds)
        (-0.5, "1969-12-31T23:59:59Z"),               // fractional, negative
        (1_700_000_000.75, "2023-11-14T22:13:20Z"),   // realistic current-era timestamp
        (951_782_400.0, "2000-02-29T00:00:00Z"),      // leap day
        (-62_135_596_800.0, "1-01-01T00:00:00Z"),     // year 1
        (253_402_300_799.0, "9999-12-31T23:59:59Z"),  // last 4-digit year
        (253_402_300_800.0, "10000-01-01T00:00:00Z"), // rolls into 5 digits
        (2_147_483_647.0, "2038-01-19T03:14:07Z"),    // i32::MAX (Y2038)
        (2_147_483_648.0, "2038-01-19T03:14:08Z"),    // one past it
        (-2_147_483_648.0, "1901-12-13T20:45:52Z"),   // i32::MIN
        (-2_147_483_649.0, "1901-12-13T20:45:51Z"),   // one past it
        (-62_167_219_200.0, "0-01-01T00:00:00Z"),     // year 0
        (-62_167_219_201.0, "-1-12-31T23:59:59Z"),    // year -1
        (1e15, "31690708-07-05T01:46:40Z"),           // an 8-digit year
    ];
    for (ts, want) in cases {
        assert_eq!(iso(Some(*ts)), *want, "iso({ts})");
    }
}

/// Out-of-range and non-finite timestamps: `iso` never panics and returns a
/// computed string; `try_iso` refuses each of them.
#[test]
fn iso_out_of_range_and_non_finite_timestamps() {
    assert_eq!(iso(Some(1e18)), "31688740476-10-23T01:46:40Z");
    assert_eq!(iso(Some(-1e18)), "-31688736537-03-10T22:13:20Z");
    assert_eq!(iso(Some(6.7768e16)), "2147484401-02-16T20:26:40Z");
    assert_eq!(iso(Some(f64::NAN)), "1970-01-01T00:00:00Z");
    assert_eq!(iso(Some(f64::INFINITY)), "292277026596-12-04T15:30:07Z");
    assert_eq!(
        iso(Some(f64::NEG_INFINITY)),
        "-292277022657-01-27T08:29:52Z"
    );
    for ts in [
        1e18,
        -1e18,
        6.7768e16,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        assert!(zeropw::store::try_iso(Some(ts)).is_err(), "try_iso({ts})");
    }
    assert_eq!(
        zeropw::store::try_iso(Some(1_700_000_000.0)).unwrap(),
        "2023-11-14T22:13:20Z"
    );
}
