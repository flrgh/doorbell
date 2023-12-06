use async_trait::async_trait;

pub trait PrimaryKey {
    type Key;

    fn primary_key(&self) -> Self::Key;
    fn primary_key_column() -> &'static str;
}

pub trait Update {
    type Updates;
    type Err;

    fn update(&mut self, updates: Self::Updates) -> Result<bool, Self::Err>;
}

#[async_trait]
pub trait Repository<T: Entity> {
    type Err;

    async fn get(&self, id: T::Key) -> Result<Option<T>, Self::Err>;

    async fn get_all(&self) -> Result<Vec<T>, Self::Err>;

    async fn insert(&self, item: T) -> Result<(), Self::Err>;

    async fn upsert(&self, item: T) -> Result<(), Self::Err>;

    async fn update(&self, id: T::Key, updates: T::Updates) -> Result<Option<T>, Self::Err>;

    async fn delete(&self, id: T::Key) -> Result<Option<T>, Self::Err>;

    async fn truncate(&self) -> Result<(), Self::Err>;
}

pub trait Validate {
    type Err;

    fn validate(&self) -> Result<(), Self::Err>;
}

pub trait Entity: Validate + PrimaryKey + Update {
    fn table_name() -> &'static str;
}
