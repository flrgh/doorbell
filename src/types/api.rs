use serde::Deserializer;

#[derive(Debug, Eq, PartialEq, Default)]
pub(crate) enum Patch<T> {
    #[default]
    Unchanged,
    Remove,
    Value(T),
}

impl<T> Patch<T> {
    pub fn update(self, field: &mut Option<T>) -> bool
    where
        T: PartialEq,
    {
        match self {
            Self::Unchanged => false,
            Self::Value(new) => UpdateChanged::update(field, new),
            Self::Remove => field.take().is_some(),
        }
    }

    pub fn is_changed(&self) -> bool {
        match self {
            Self::Unchanged => false,
            Self::Value(_) => true,
            Self::Remove => true,
        }
    }
}

impl<T> From<Option<T>> for Patch<T> {
    fn from(opt: Option<T>) -> Patch<T> {
        match opt {
            Some(v) => Patch::Value(v),
            None => Patch::Remove,
        }
    }
}

// serde doesn't give us any straightforward means of differentiating between
// an object field that is null and an object field that is not set.
//
// The only way we can observe the difference between the two is by instructing
// serde to use the default value for a field, so now:
//
// * field is not set    => Patch::Unchanged
// * field is null       => Patch::Remove
// * field is non-null   => Patch::Value(_)
impl<'de, T> serde::Deserialize<'de> for Patch<T>
where
    T: serde::Deserialize<'de>,
    T: std::fmt::Debug,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::deserialize(deserializer).map(Into::into)
    }
}

trait UpdateChanged<T> {
    fn update(&mut self, t: T) -> bool;
}

impl<T: PartialEq> UpdateChanged<T> for Option<T> {
    fn update(&mut self, t: T) -> bool {
        let old = self.take();
        let changed = old.is_none() || old.is_some_and(|old| old != t);
        let _ = self.insert(t);
        changed
    }
}
