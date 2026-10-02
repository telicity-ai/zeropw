use std::cmp::Ordering;
use std::process::Command;
use std::str::FromStr;

use num_bigint::BigInt;

#[test]
fn bigint_float_comparison_matches_cpython_boundaries() {
    let cases = [
        ("9007199254740993".into(), 9_007_199_254_740_992.0),
        ("9007199254740994".into(), 9_007_199_254_740_994.0),
        ("-9007199254740993".into(), -9_007_199_254_740_992.0),
        ("1".into(), 1.5),
        ("-2".into(), -1.5),
        (format!("1{}", "0".repeat(400)), f64::INFINITY),
        (format!("-1{}", "0".repeat(400)), f64::NEG_INFINITY),
        ("0".into(), f64::NAN),
    ];
    let expressions = [
        "(9007199254740993, 9007199254740992.0)",
        "(9007199254740994, 9007199254740994.0)",
        "(-9007199254740993, -9007199254740992.0)",
        "(1, 1.5)",
        "(-2, -1.5)",
        "(10**400, float('inf'))",
        "(-(10**400), float('-inf'))",
        "(0, float('nan'))",
    ];
    let script = format!(
        "pairs=[{}]\nfor i,f in pairs:\n print('u' if not (i<f or i==f or i>f) else (-1 if i<f else (0 if i==f else 1)))",
        expressions.join(",")
    );
    let interpreter = std::env::var("ZEROPW_PYTHON").unwrap_or_else(|_| "python3.12".into());
    let output = Command::new(interpreter)
        .arg("-I")
        .arg("-c")
        .arg(script)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let expected: Vec<&str> = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .collect();
    for ((integer, float), expected) in cases.into_iter().zip(expected) {
        let actual = zeropw::pyint::cmp_bigint_f64(&BigInt::from_str(&integer).unwrap(), float);
        let actual = match actual {
            Some(Ordering::Less) => "-1",
            Some(Ordering::Equal) => "0",
            Some(Ordering::Greater) => "1",
            None => "u",
        };
        assert_eq!(actual, expected, "{integer} compared with {float:?}");
    }
}
