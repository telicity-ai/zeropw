//! `pyint::cmp_bigint_f64`: exact comparison of an unbounded integer with a
//! float (Python's `int`/`float` comparison semantics, which persisted
//! integer fields compared against float timestamps rely on). The expected
//! orderings are the mathematically exact ones.
use std::cmp::Ordering;
use std::str::FromStr;

use num_bigint::BigInt;

#[test]
fn bigint_float_comparison_is_exact_at_the_boundaries() {
    let cases: [(String, f64, Option<Ordering>); 8] = [
        // 2**53 + 1 is not representable: the float is 2**53, so the int is greater.
        (
            "9007199254740993".into(),
            9_007_199_254_740_992.0,
            Some(Ordering::Greater),
        ),
        (
            "9007199254740994".into(),
            9_007_199_254_740_994.0,
            Some(Ordering::Equal),
        ),
        (
            "-9007199254740993".into(),
            -9_007_199_254_740_992.0,
            Some(Ordering::Less),
        ),
        ("1".into(), 1.5, Some(Ordering::Less)),
        ("-2".into(), -1.5, Some(Ordering::Less)),
        (
            format!("1{}", "0".repeat(400)),
            f64::INFINITY,
            Some(Ordering::Less),
        ),
        (
            format!("-1{}", "0".repeat(400)),
            f64::NEG_INFINITY,
            Some(Ordering::Greater),
        ),
        // NaN is unordered with everything.
        ("0".into(), f64::NAN, None),
    ];
    for (integer, float, expected) in cases {
        let actual = zeropw::pyint::cmp_bigint_f64(&BigInt::from_str(&integer).unwrap(), float);
        assert_eq!(actual, expected, "{integer} compared with {float:?}");
    }
}
