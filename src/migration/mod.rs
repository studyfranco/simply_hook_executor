//! Database migration registry for `simply_hook_executor`. Migrations run automatically on
//! startup.
pub use sea_orm_migration::prelude::*;

mod m20230101_000001_initial_schema;
mod m20230102_000001_add_run_as_user;
mod m20230103_000001_add_signing_secret;
mod m20230104_000001_add_hmac_mode;

/// The ordered set of all schema migrations for `simply_hook_executor`.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230101_000001_initial_schema::Migration),
            Box::new(m20230102_000001_add_run_as_user::Migration),
            Box::new(m20230103_000001_add_signing_secret::Migration),
            Box::new(m20230104_000001_add_hmac_mode::Migration),
        ]
    }
}
