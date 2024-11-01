use crate::error::{Error, Result, UnsupportedType};
use crate::Field;
use alloc::collections::BTreeMap;
use serde::de;
use serde::de::IntoDeserializer;
use tangle_subxt::subxt_core::utils::AccountId32;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::bounded_collections::bounded_vec::BoundedVec;
use tangle_subxt::tangle_testnet_runtime::api::runtime_types::tangle_primitives::services::field::FieldType;

/// Wrapper from `Field<AccountId32>`, since it's an external type.
pub struct Deserializer(pub(crate) Field<AccountId32>);

impl<'de> de::Deserializer<'de> for Deserializer {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.0 {
            Field::None => visitor.visit_none(),
            Field::Bool(b) => visitor.visit_bool(b),
            Field::Uint8(u) => visitor.visit_u8(u),
            Field::Int8(i) => visitor.visit_i8(i),
            Field::Uint16(u) => visitor.visit_u16(u),
            Field::Int16(i) => visitor.visit_i16(i),
            Field::Uint32(u) => visitor.visit_u32(u),
            Field::Int32(i) => visitor.visit_i32(i),
            Field::Uint64(u) => visitor.visit_u64(u),
            Field::Int64(i) => visitor.visit_i64(i),
            Field::String(s) => {
                let s = String::from_utf8(s.0 .0)?;
                visitor.visit_string(s)
            }
            Field::Bytes(b) => visitor.visit_bytes(b.0.as_slice()),
            Field::Array(seq) | Field::List(seq) => visit_seq(seq.0, visitor),
            Field::Struct(_, _) => todo!(),
            Field::AccountId(_) => todo!(),
        }
    }

    fn deserialize_bool<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_bool(self.strip_bool()?)
    }

    fn deserialize_i8<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_i8(self.strip_i8()?)
    }

    fn deserialize_i16<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_i16(self.strip_i16()?)
    }

    fn deserialize_i32<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_i32(self.strip_i32()?)
    }

    fn deserialize_i64<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_i64(self.strip_i64()?)
    }

    fn deserialize_u8<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_u8(self.strip_u8()?)
    }

    fn deserialize_u16<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_u16(self.strip_u16()?)
    }

    fn deserialize_u32<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_u32(self.strip_u32()?)
    }

    fn deserialize_u64<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_u64(self.strip_u64()?)
    }

    fn deserialize_f32<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType(UnsupportedType::f32))
    }

    fn deserialize_f64<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType(UnsupportedType::f64))
    }

    fn deserialize_char<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        let string = self.strip_string()?;
        let mut chars = string.chars();
        let Some(ch) = chars.next() else {
            return Err(Error::BadCharLength(0));
        };

        if chars.next().is_some() {
            return Err(Error::BadCharLength(chars.count().saturating_add(2)));
        }

        visitor.visit_char(ch)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_string(visitor)
    }

    fn deserialize_string<V>(mut self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_string(self.strip_string()?)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_byte_buf(visitor)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.0 {
            Field::Bytes(seq) => visitor.visit_byte_buf(seq.0),
            Field::String(s) => visitor.visit_string(String::from_utf8(s.0 .0)?),
            _ => Err(self.invalid_type(&visitor)),
        }
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.0 {
            Field::None => visitor.visit_none(),
            _ => visitor.visit_some(self),
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.0 {
            Field::None => visitor.visit_unit(),
            _ => Err(self.invalid_type(&visitor)),
        }
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.0 {
            Field::Array(seq) | Field::List(seq) => visit_seq(seq.0, visitor),
            _ => Err(self.invalid_type(&visitor)),
        }
    }

    fn deserialize_tuple<V>(self, _len: usize, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.0 {
            Field::Struct(_, fields) => {
                let mut values = Vec::with_capacity(fields.0.len());
                for (_, field) in fields.0 {
                    values.push(field);
                }

                visit_seq(values, visitor)
            }
            _ => Err(self.invalid_type(&visitor)),
        }
    }

    fn deserialize_map<V>(self, _visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        Err(Error::UnsupportedType(UnsupportedType::Map))
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        match self.0 {
            Field::Struct(_name, f) => {
                let mut fields = BTreeMap::new();
                for (name, value) in f.0 {
                    let name = String::from_utf8(name.0 .0)?;
                    fields.insert(name, value);
                }

                visit_struct(fields, visitor)
            }
            _ => Err(self.invalid_type(&visitor)),
        }
    }

    fn deserialize_enum<V>(
        mut self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        // Only accept unit variants
        let variant = self.strip_string()?;
        visitor.visit_enum(variant.into_deserializer())
    }

    fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value>
    where
        V: de::Visitor<'de>,
    {
        visitor.visit_unit()
    }
}

impl Deserializer {
    #[cold]
    fn invalid_type<E>(&self, exp: &dyn de::Expected) -> E
    where
        E: de::Error,
    {
        de::Error::invalid_type(self.unexpected(), exp)
    }

    #[cold]
    fn unexpected(&self) -> de::Unexpected<'_> {
        match &self.0 {
            Field::None => de::Unexpected::Unit,
            Field::Bool(b) => de::Unexpected::Bool(*b),

            Field::Uint8(u) => de::Unexpected::Unsigned(u64::from(*u)),
            Field::Uint16(u) => de::Unexpected::Unsigned(u64::from(*u)),
            Field::Uint32(u) => de::Unexpected::Unsigned(u64::from(*u)),
            Field::Uint64(u) => de::Unexpected::Unsigned(*u),

            Field::Int8(i) => de::Unexpected::Signed(i64::from(*i)),
            Field::Int16(i) => de::Unexpected::Signed(i64::from(*i)),
            Field::Int32(i) => de::Unexpected::Signed(i64::from(*i)),
            Field::Int64(i) => de::Unexpected::Signed(*i),

            Field::String(s) => de::Unexpected::Str(core::str::from_utf8(&s.0 .0).unwrap_or("")),
            Field::Bytes(b) => de::Unexpected::Bytes(b.0.as_slice()),
            Field::Array(_) | Field::List(_) => de::Unexpected::Seq,
            Field::Struct(_, _) => de::Unexpected::Other("Struct"),
            Field::AccountId(_) => de::Unexpected::Other("AccountId"),
        }
    }
}

macro_rules! define_strip_methods {
    ($([$fn:ident, $ty:ty, $expected_field_ty:path, $pat:pat]),+ $(,)?) => {
        $(
            paste::paste! {
                fn $fn(&mut self) -> Result<$ty> {
                    match self.0 {
                        $pat(v) => {
                            Ok(v)
                        },
                        ref v => Err(Error::UnexpectedType {
                            expected: $expected_field_ty,
                            actual: field_type_for_field(v)
                        })
                    }
                }
            }
        )+
    }
}

impl Deserializer {
    define_strip_methods! {
        [strip_bool, bool, FieldType::Bool, Field::Bool],
        [strip_i8,   i8,   FieldType::Int8,   Field::Int8],
        [strip_i16,  i16,  FieldType::Int16,  Field::Int16],
        [strip_i32,  i32,  FieldType::Int32,  Field::Int32],
        [strip_i64,  i64,  FieldType::Int64,  Field::Int64],
        [strip_u8,   u8,   FieldType::Uint8,   Field::Uint8],
        [strip_u16,  u16,  FieldType::Uint16,  Field::Uint16],
        [strip_u32,  u32,  FieldType::Uint32,  Field::Uint32],
        [strip_u64,  u64,  FieldType::Uint64,  Field::Uint64],
    }

    fn strip_string(&mut self) -> Result<String> {
        let val = core::mem::replace(&mut self.0, Field::None);
        match val {
            Field::String(bound_string) => String::from_utf8(bound_string.0 .0).map_err(Into::into),
            _ => Err(Error::UnexpectedType {
                expected: FieldType::String,
                actual: field_type_for_field(&val),
            }),
        }
    }
}

fn field_type_for_field(field: &Field<AccountId32>) -> Option<FieldType> {
    match field {
        Field::None => None,
        Field::Bool(_) => Some(FieldType::Bool),
        Field::Uint8(_) => Some(FieldType::Uint8),
        Field::Int8(_) => Some(FieldType::Int8),
        Field::Uint16(_) => Some(FieldType::Uint16),
        Field::Int16(_) => Some(FieldType::Int16),
        Field::Uint32(_) => Some(FieldType::Uint32),
        Field::Int32(_) => Some(FieldType::Int32),
        Field::Uint64(_) => Some(FieldType::Uint64),
        Field::Int64(_) => Some(FieldType::Int64),
        Field::String(_) => Some(FieldType::String),
        Field::Bytes(_) => Some(FieldType::Bytes),
        Field::Array(v) => {
            let len = v.0.len() as u64;
            if len == 0 {
                return None;
            }

            let ty = field_type_for_field(&v.0[0])?;
            Some(FieldType::Array(len, Box::new(ty)))
        }
        Field::List(v) => {
            if v.0.is_empty() {
                return None;
            }

            let ty = field_type_for_field(&v.0[0])?;
            Some(FieldType::List(Box::new(ty)))
        }
        Field::Struct(_, f) => {
            let mut fields = Vec::with_capacity(f.0.len());
            for (_, field_value) in &f.0 {
                let ty = field_type_for_field(field_value)?;
                fields.push((FieldType::String, ty));
            }

            Some(FieldType::Struct(
                Box::new(FieldType::String),
                Box::new(BoundedVec(fields)),
            ))
        }
        Field::AccountId(_) => Some(FieldType::AccountId),
    }
}

struct StructDeserializer {
    iter: <BTreeMap<String, Field<AccountId32>> as IntoIterator>::IntoIter,
    field: Option<Field<AccountId32>>,
}

impl StructDeserializer {
    fn new(map: BTreeMap<String, Field<AccountId32>>) -> Self {
        StructDeserializer {
            iter: map.into_iter(),
            field: None,
        }
    }
}

impl<'de> de::MapAccess<'de> for StructDeserializer {
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>>
    where
        K: de::DeserializeSeed<'de>,
    {
        match self.iter.next() {
            Some((key, field)) => {
                self.field = Some(field);
                seed.deserialize(key.into_deserializer()).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value>
    where
        V: de::DeserializeSeed<'de>,
    {
        match self.field.take() {
            Some(field) => seed.deserialize(Deserializer(field)),
            None => Err(serde::de::Error::custom("value is missing")),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self.iter.size_hint() {
            (lower, Some(upper)) if lower == upper => Some(upper),
            _ => None,
        }
    }
}

fn visit_struct<'de, V>(s: BTreeMap<String, Field<AccountId32>>, visitor: V) -> Result<V::Value>
where
    V: de::Visitor<'de>,
{
    let len = s.len();
    let mut de = StructDeserializer::new(s);
    let seq = visitor.visit_map(&mut de)?;
    let remaining = de.iter.len();
    if remaining == 0 {
        Ok(seq)
    } else {
        Err(de::Error::invalid_length(len, &"fewer elements in struct"))
    }
}

struct SeqDeserializer {
    iter: alloc::vec::IntoIter<Field<AccountId32>>,
}

impl SeqDeserializer {
    fn new(vec: Vec<Field<AccountId32>>) -> Self {
        SeqDeserializer {
            iter: vec.into_iter(),
        }
    }
}

impl<'de> de::SeqAccess<'de> for SeqDeserializer {
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>>
    where
        T: de::DeserializeSeed<'de>,
    {
        match self.iter.next() {
            Some(field) => seed.deserialize(Deserializer(field)).map(Some),
            None => Ok(None),
        }
    }

    fn size_hint(&self) -> Option<usize> {
        match self.iter.size_hint() {
            (lower, Some(upper)) if lower == upper => Some(upper),
            _ => None,
        }
    }
}

fn visit_seq<'de, V>(seq: Vec<Field<AccountId32>>, visitor: V) -> Result<V::Value>
where
    V: de::Visitor<'de>,
{
    let len = seq.len();
    let mut de = SeqDeserializer::new(seq);
    let seq = visitor.visit_seq(&mut de)?;
    let remaining = de.iter.len();
    if remaining == 0 {
        Ok(seq)
    } else {
        Err(de::Error::invalid_length(
            len,
            &"fewer elements in sequence",
        ))
    }
}