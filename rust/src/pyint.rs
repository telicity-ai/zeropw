//! Exact Python integer values at JSON boundaries. Never serialize `BigInt`
//! through its limb-based Serde representation: state and public mappings use
//! ordinary JSON decimal numbers.
use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use num_bigint::BigInt;
use serde::{Serialize, Serializer};
use serde_json::{Number, Value};

#[derive(Clone, Debug, Eq, Hash, PartialEq, Ord, PartialOrd)]
pub struct PyInt(pub BigInt);

impl PyInt {
    /// CPython's `int(value)` for values that can arrive through JSON.
    ///
    /// This accepts integer and finite-float numbers, booleans, and strings
    /// accepted by the canonical Python decimal-string parser (including its
    /// configured digit limit). Other JSON shapes and non-finite floats are
    /// not coercible.
    pub fn coerce_from_json(value: &Value) -> Option<Self> {
        let integer = match value {
            Value::Number(number) if crate::pyjson::is_float_literal(number.as_str()) => {
                let float = number.as_f64()?;
                if !float.is_finite() {
                    return None;
                }
                let bits = float.to_bits();
                let negative = bits >> 63 != 0;
                let exponent = ((bits >> 52) & 0x7ff) as i32;
                let fraction = bits & ((1_u64 << 52) - 1);
                let mut integer = if exponent == 0 {
                    BigInt::from(0)
                } else {
                    let significand = BigInt::from((1_u64 << 52) | fraction);
                    let shift = exponent - 1023 - 52;
                    if shift >= 0 {
                        significand << shift as usize
                    } else {
                        significand >> (-shift) as usize
                    }
                };
                if negative {
                    integer = -integer;
                }
                integer
            }
            Value::Number(number) => BigInt::from_str(number.as_str()).ok()?,
            Value::Bool(boolean) => BigInt::from(u8::from(*boolean)),
            Value::String(string) => {
                BigInt::from_str(&crate::pystr::int_from_str_decimal_limited(string)?).ok()?
            }
            _ => return None,
        };
        Some(Self(integer))
    }

    pub fn from_json_integer(value: &Value) -> Option<Self> {
        match value {
            Value::Number(_) => {
                let text = crate::pyjson::dumps(value, crate::pyjson::DumpOptions::plain()).ok()?;
                // Python configuration integers reject JSON fractional or
                // exponent notation, even if numerically integral.
                BigInt::from_str(&text).ok().map(Self)
            }
            _ => None,
        }
    }

    pub fn from_python_int(value: &Value) -> Option<Self> {
        match value {
            Value::Bool(v) => Some(Self(BigInt::from(u8::from(*v)))),
            _ => Self::from_json_integer(value),
        }
    }

    pub fn value(&self) -> Value {
        let number = Number::from_str(&self.0.to_string()).expect("BigInt is a JSON integer");
        Value::Number(number)
    }
}

/// Compare a Python `int` with a binary64 Python `float` without converting
/// the integer to `f64`. CPython's rich comparison keeps the integer exact,
/// including beyond 2**53. NaN is unordered; infinities sort outside every
/// finite integer.
pub fn cmp_bigint_f64(integer: &BigInt, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float == f64::INFINITY {
        return Some(Ordering::Less);
    }
    if float == f64::NEG_INFINITY {
        return Some(Ordering::Greater);
    }

    let bits = float.to_bits();
    let negative = bits >> 63 != 0;
    let exponent_bits = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1_u64 << 52) - 1);
    let (mantissa, exponent) = if exponent_bits == 0 {
        (fraction, -1074)
    } else {
        ((1_u64 << 52) | fraction, exponent_bits - 1023 - 52)
    };
    let signed_mantissa = if negative {
        -BigInt::from(mantissa)
    } else {
        BigInt::from(mantissa)
    };
    if exponent >= 0 {
        Some(integer.cmp(&(signed_mantissa << exponent as usize)))
    } else {
        Some((integer << (-exponent) as usize).cmp(&signed_mantissa))
    }
}

impl From<i64> for PyInt {
    fn from(value: i64) -> Self {
        Self(BigInt::from(value))
    }
}

impl From<i32> for PyInt {
    fn from(value: i32) -> Self {
        Self(BigInt::from(value))
    }
}

impl From<u16> for PyInt {
    fn from(value: u16) -> Self {
        Self(BigInt::from(value))
    }
}

impl PartialEq<u16> for PyInt {
    fn eq(&self, other: &u16) -> bool {
        self.0 == BigInt::from(*other)
    }
}

macro_rules! partial_eq_integer {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl PartialEq<$ty> for PyInt {
                fn eq(&self, other: &$ty) -> bool {
                    self.0 == BigInt::from(*other)
                }
            }
        )+
    };
}

partial_eq_integer!(i64, u64, usize);

impl fmt::Display for PyInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq<i32> for PyInt {
    fn eq(&self, other: &i32) -> bool {
        self.0 == BigInt::from(*other)
    }
}

impl Serialize for PyInt {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.value().serialize(serializer)
    }
}
