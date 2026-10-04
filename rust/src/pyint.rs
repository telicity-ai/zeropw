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

    /// The value as an `i64`, or `None` when it lies outside that range.
    pub fn to_i64(&self) -> Option<i64> {
        i64::try_from(&self.0).ok()
    }
}

/// Python `int + int` / `int - int`: unbounded, never overflows.
macro_rules! int_arithmetic {
    ($($trait:ident $method:ident),+ $(,)?) => {
        $(
            impl std::ops::$trait<i64> for PyInt {
                type Output = PyInt;
                fn $method(self, rhs: i64) -> PyInt {
                    PyInt(std::ops::$trait::$method(self.0, BigInt::from(rhs)))
                }
            }

            impl std::ops::$trait<i64> for &PyInt {
                type Output = PyInt;
                fn $method(self, rhs: i64) -> PyInt {
                    PyInt(std::ops::$trait::$method(&self.0, BigInt::from(rhs)))
                }
            }
        )+
    };
}

int_arithmetic!(Add add, Sub sub);

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

impl From<i128> for PyInt {
    fn from(value: i128) -> Self {
        Self(BigInt::from(value))
    }
}

impl From<u64> for PyInt {
    fn from(value: u64) -> Self {
        Self(BigInt::from(value))
    }
}

impl From<usize> for PyInt {
    fn from(value: usize) -> Self {
        Self(BigInt::from(value))
    }
}

impl From<BigInt> for PyInt {
    fn from(value: BigInt) -> Self {
        Self(value)
    }
}

impl From<&PyInt> for PyInt {
    fn from(value: &PyInt) -> Self {
        value.clone()
    }
}

partial_eq_integer!(i128);

impl PartialOrd<i64> for PyInt {
    fn partial_cmp(&self, other: &i64) -> Option<Ordering> {
        Some(self.0.cmp(&BigInt::from(*other)))
    }
}

impl PartialOrd<i128> for PyInt {
    fn partial_cmp(&self, other: &i128) -> Option<Ordering> {
        Some(self.0.cmp(&BigInt::from(*other)))
    }
}

impl PartialOrd<i32> for PyInt {
    fn partial_cmp(&self, other: &i32) -> Option<Ordering> {
        Some(self.0.cmp(&BigInt::from(*other)))
    }
}

impl PyInt {
    pub fn zero() -> Self {
        Self(BigInt::from(0))
    }

    /// CPython's `float(int)` (`PyLong_AsDouble`): the correctly rounded
    /// (round-half-to-even) binary64 value, or `None` where CPython raises
    /// `OverflowError: int too large to convert to float`.
    pub fn to_f64(&self) -> Option<f64> {
        bigint_to_f64(&self.0)
    }
}

/// See [`PyInt::to_f64`].
pub fn bigint_to_f64(value: &BigInt) -> Option<f64> {
    let negative = value.sign() == num_bigint::Sign::Minus;
    let magnitude = value.magnitude();
    let bits = magnitude.bits();
    let unsigned = if bits <= 53 {
        u64::try_from(magnitude).ok()? as f64
    } else {
        // Keep 54 significant bits (53 + one rounding bit); every lower bit
        // is folded into a sticky flag.
        let shift = bits - 54;
        let top = u64::try_from(&(magnitude >> shift)).ok()?;
        let sticky = magnitude
            .trailing_zeros()
            .is_some_and(|zeros| zeros < shift);
        let mut mantissa = top >> 1;
        if top & 1 == 1 && (sticky || mantissa & 1 == 1) {
            mantissa += 1;
        }
        let exponent = i32::try_from(shift + 1).ok()?;
        if exponent > 1023 {
            return None;
        }
        let scaled = mantissa as f64 * 2f64.powi(exponent);
        if !scaled.is_finite() {
            return None;
        }
        scaled
    };
    Some(if negative { -unsigned } else { unsigned })
}

/// A Python `int` or `float` produced by arithmetic over JSON numbers.
#[derive(Clone, Debug, PartialEq)]
pub enum PyNumber {
    Int(BigInt),
    Float(f64),
}

impl PyNumber {
    /// A JSON number or bool as the Python value `json.load` produces;
    /// `None` for every other shape (not a number in Python either).
    pub fn from_json(value: &Value) -> Option<Self> {
        match value {
            Value::Bool(boolean) => Some(Self::Int(BigInt::from(u8::from(*boolean)))),
            Value::Number(number) if crate::pyjson::is_float_literal(number.as_str()) => {
                number.as_str().parse::<f64>().ok().map(Self::Float)
            }
            Value::Number(number) => BigInt::from_str(number.as_str()).ok().map(Self::Int),
            _ => None,
        }
    }

    /// `a + b` (`PyNumber_Add`); `None` for CPython's `OverflowError` when an
    /// `int` operand cannot convert to `float`.
    pub fn add(&self, other: &Self) -> Option<Self> {
        Some(match (self, other) {
            (Self::Int(a), Self::Int(b)) => Self::Int(a + b),
            (Self::Int(a), Self::Float(b)) => Self::Float(bigint_to_f64(a)? + b),
            (Self::Float(a), Self::Int(b)) => Self::Float(a + bigint_to_f64(b)?),
            (Self::Float(a), Self::Float(b)) => Self::Float(a + b),
        })
    }

    /// `a - b`, same conversion rules as [`PyNumber::add`].
    pub fn sub(&self, other: &Self) -> Option<Self> {
        Some(match (self, other) {
            (Self::Int(a), Self::Int(b)) => Self::Int(a - b),
            (Self::Int(a), Self::Float(b)) => Self::Float(bigint_to_f64(a)? - b),
            (Self::Float(a), Self::Int(b)) => Self::Float(a - bigint_to_f64(b)?),
            (Self::Float(a), Self::Float(b)) => Self::Float(a - b),
        })
    }

    /// `self >= other` for an `int` right operand, comparing exactly (no
    /// `float` conversion of the integer), as CPython's rich comparison does.
    pub fn ge_int(&self, other: &BigInt) -> bool {
        match self {
            Self::Int(value) => value >= other,
            Self::Float(value) => {
                matches!(
                    cmp_bigint_f64(other, *value),
                    Some(Ordering::Less | Ordering::Equal)
                )
            }
        }
    }

    pub fn value(&self) -> Value {
        match self {
            Self::Int(value) => PyInt(value.clone()).value(),
            Self::Float(value) => serde_json::Number::from_f64(*value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
        }
    }
}

/// CPython 3.12's built-in `sum(values)` (start `0`) over JSON values, in
/// `builtin_sum_impl`'s three stages: an exact C-`long` integer fast path, a
/// Neumaier-compensated `float` fast path (entered when the running result
/// becomes a `float`; a C-`long` `int`/`bool` item is added there as an
/// uncompensated `(double)` conversion), and a generic `PyNumber_Add` loop
/// once neither fast path applies. `None` where CPython raises: a
/// non-number item (`TypeError`) or an `int` too large for `float`
/// (`OverflowError`).
pub fn python_sum<'a>(values: impl IntoIterator<Item = &'a Value>) -> Option<PyNumber> {
    let mut items = values.into_iter();
    // Stage 1: `i_result` in a C long.
    let mut i_result: i64 = 0;
    let mut result: PyNumber = loop {
        let Some(item) = items.next() else {
            return Some(PyNumber::Int(BigInt::from(i_result)));
        };
        let item = PyNumber::from_json(item)?;
        if let PyNumber::Int(b) = &item
            && let Ok(b) = i64::try_from(b)
            && let Some(sum) = i_result.checked_add(b)
        {
            i_result = sum;
            continue;
        }
        break PyNumber::Int(BigInt::from(i_result)).add(&item)?;
    };
    // Stage 2: the float fast path.
    if let PyNumber::Float(mut f_result) = result {
        let mut c = 0.0_f64;
        loop {
            let Some(item) = items.next() else {
                if c != 0.0 && c.is_finite() {
                    f_result += c;
                }
                return Some(PyNumber::Float(f_result));
            };
            let item = PyNumber::from_json(item)?;
            match &item {
                PyNumber::Float(x) => {
                    let t = f_result + x;
                    if f_result.abs() >= x.abs() {
                        c += (f_result - t) + x;
                    } else {
                        c += (x - t) + f_result;
                    }
                    f_result = t;
                    continue;
                }
                PyNumber::Int(b) => {
                    if let Ok(b) = i64::try_from(b) {
                        f_result += b as f64;
                        continue;
                    }
                }
            }
            if c != 0.0 && c.is_finite() {
                f_result += c;
            }
            result = PyNumber::Float(f_result).add(&item)?;
            break;
        }
    }
    // Stage 3: generic addition.
    for item in items {
        result = result.add(&PyNumber::from_json(item)?)?;
    }
    Some(result)
}
