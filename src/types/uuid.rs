use serde_derive::{Deserialize, Serialize};
use sqlx::{
    database::HasValueRef, encode::IsNull, error::BoxDynError, sqlite::SqliteArgumentValue,
    Database, Decode, Encode, Sqlite, Type,
};
use std::{borrow::Cow, fmt::Display, result::Result, str::FromStr};

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub struct Uuid(pub uuid::Uuid);

impl Uuid {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    pub fn into_inner(self) -> uuid::Uuid {
        self.0
    }
}

impl AsRef<uuid::Uuid> for Uuid {
    fn as_ref(&self) -> &uuid::Uuid {
        &self.0
    }
}

impl Default for Uuid {
    fn default() -> Self {
        Self::new()
    }
}

impl<DB> Type<DB> for Uuid
where
    String: Type<DB>,
    DB: Database,
{
    fn type_info() -> DB::TypeInfo {
        String::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        String::compatible(ty)
    }
}

impl<'r, DB: Database> Decode<'r, DB> for Uuid
where
    &'r str: Decode<'r, DB>,
{
    fn decode(value: <DB as HasValueRef<'r>>::ValueRef) -> Result<Self, BoxDynError> {
        let value = <&str as Decode<DB>>::decode(value)?;

        let uuid: uuid::Uuid = value.parse()?;

        Ok(Uuid(uuid))
    }
}

impl<'q> Encode<'q, Sqlite> for &'q Uuid
where
    &'q str: Encode<'q, Sqlite>,
    &'q Uuid: std::fmt::Display,
{
    fn encode_by_ref(&self, args: &mut Vec<SqliteArgumentValue<'q>>) -> IsNull {
        args.push(SqliteArgumentValue::Text(Cow::Owned(self.to_string())));

        IsNull::No
    }
}

impl FromStr for Uuid {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl PartialEq<uuid::Uuid> for Uuid {
    fn eq(&self, other: &uuid::Uuid) -> bool {
        &(self.0) == other
    }
}

impl From<Uuid> for uuid::Uuid {
    fn from(value: Uuid) -> Self {
        value.into_inner()
    }
}

impl From<uuid::Uuid> for Uuid {
    fn from(value: uuid::Uuid) -> Self {
        Self(value)
    }
}

impl Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<Uuid> for String {
    fn from(value: Uuid) -> Self {
        value.0.to_string()
    }
}
