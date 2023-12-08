use cidr_utils::cidr;
use serde_derive::{Deserialize, Serialize};
use sqlx::{
    database::HasValueRef, encode::IsNull, error::BoxDynError, sqlite::SqliteArgumentValue,
    Database, Decode, Encode, Sqlite, Type,
};
use std::{
    borrow::Cow, fmt::Display, net, ops::Deref, ops::DerefMut, result::Result, str::FromStr,
};

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[repr(transparent)]
pub struct IpAddr(pub net::IpAddr);

impl<DB> Type<DB> for IpAddr
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

impl IpAddr {
    pub fn into_inner(self) -> net::IpAddr {
        self.0
    }
}

impl AsRef<net::IpAddr> for IpAddr {
    fn as_ref(&self) -> &net::IpAddr {
        &self.0
    }
}

impl AsMut<net::IpAddr> for IpAddr {
    fn as_mut(&mut self) -> &mut net::IpAddr {
        &mut self.0
    }
}

impl Deref for IpAddr {
    type Target = net::IpAddr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for IpAddr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl FromStr for IpAddr {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl PartialEq<net::IpAddr> for IpAddr {
    fn eq(&self, other: &net::IpAddr) -> bool {
        &(self.0) == other
    }
}

impl From<IpAddr> for net::IpAddr {
    fn from(value: IpAddr) -> Self {
        value.0
    }
}

impl From<net::IpAddr> for IpAddr {
    fn from(value: net::IpAddr) -> Self {
        Self(value)
    }
}

impl Display for IpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'r, DB: Database> Decode<'r, DB> for IpAddr
where
    &'r str: Decode<'r, DB>,
{
    fn decode(value: <DB as HasValueRef<'r>>::ValueRef) -> Result<Self, BoxDynError> {
        let value = <&str as Decode<DB>>::decode(value)?;

        let addr: net::IpAddr = value.parse()?;

        Ok(IpAddr(addr))
    }
}

impl<'q> Encode<'q, Sqlite> for &'q IpAddr
where
    &'q str: Encode<'q, Sqlite>,
    &'q IpAddr: std::fmt::Display,
{
    fn encode_by_ref(&self, args: &mut Vec<SqliteArgumentValue<'q>>) -> IsNull {
        args.push(SqliteArgumentValue::Text(Cow::Owned(self.to_string())));

        IsNull::No
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
#[repr(transparent)]
pub struct IpCidr(pub cidr::IpCidr);

impl<'r, DB: Database> Decode<'r, DB> for IpCidr
where
    &'r str: Decode<'r, DB>,
{
    fn decode(value: <DB as HasValueRef<'r>>::ValueRef) -> Result<Self, BoxDynError> {
        let value = <&str as Decode<DB>>::decode(value)?;

        let addr: cidr::IpCidr = value.parse()?;

        Ok(IpCidr(addr))
    }
}

impl FromStr for IpCidr {
    type Err = cidr_utils::cidr::IpCidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.parse()?))
    }
}

impl From<IpCidr> for cidr::IpCidr {
    fn from(value: IpCidr) -> Self {
        value.0
    }
}

impl Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl From<cidr::IpCidr> for IpCidr {
    fn from(value: cidr::IpCidr) -> Self {
        Self(value)
    }
}

impl IpCidr {
    pub fn into_inner(self) -> cidr::IpCidr {
        self.0
    }

    pub fn contains<T>(&self, addr: &T) -> bool
    where
        T: AsRef<std::net::IpAddr>,
    {
        self.0.contains(*addr.as_ref())
    }
}

impl AsRef<cidr::IpCidr> for IpCidr {
    fn as_ref(&self) -> &cidr::IpCidr {
        &self.0
    }
}

impl<'q> Encode<'q, Sqlite> for &'q IpCidr
where
    &'q str: Encode<'q, Sqlite>,
{
    fn encode_by_ref(&self, args: &mut Vec<SqliteArgumentValue<'q>>) -> IsNull {
        args.push(SqliteArgumentValue::Text(Cow::Owned(self.to_string())));

        IsNull::No
    }
}

impl<DB> Type<DB> for IpCidr
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

impl Deref for IpCidr {
    type Target = cidr::IpCidr;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for IpCidr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsMut<cidr::IpCidr> for IpCidr {
    fn as_mut(&mut self) -> &mut cidr::IpCidr {
        &mut self.0
    }
}
