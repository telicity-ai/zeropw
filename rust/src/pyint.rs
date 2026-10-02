//! Exact Python integer values at JSON boundaries. Never serialize `BigInt`
//! through its limb-based Serde representation: state and public mappings use
//! ordinary JSON decimal numbers.
use std::str::FromStr;

use num_bigint::BigInt;
use serde::{Serialize, Serializer};
use serde_json::{Number, Value};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PyInt(pub BigInt);

impl PyInt {
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

impl From<i64> for PyInt {
    fn from(value: i64) -> Self {
        Self(BigInt::from(value))
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
