#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    PartialOrd,
    Ord,
    Default,
    strum_macros::Display,
    strum_macros::EnumString,
    strum_macros::EnumIs,
    sqlx::Type,
    serde_derive::Deserialize,
    serde_derive::Serialize,
)]
#[strum(serialize_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Deny,
    Allow,
}
