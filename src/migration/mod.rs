//! Database migration registry for `simply_hook_executor`. Migrations run automatically on
//! startup.
pub use sea_orm_migration::prelude::*;

mod m20230101_090000_initial_schema;
mod m20230102_090000_add_run_as_user;
mod m20230103_090000_add_signing_secret;
mod m20230104_090000_add_hmac_mode;
mod m20230105_090000_add_hook_soft_delete;
mod m20230106_090000_master_key_uniqueness;
mod m20230107_090000_key_lineage_and_resource_ownership;
mod m20260809_090000_add_can_view_execution;
mod m20260810_090000_drop_api_key_owner_key_id;
mod m20260819_120414_add_hook_auth_mode;
mod m20260819_141730_consolidate_hmac_modes;

/// The ordered set of all schema migrations for `simply_hook_executor`.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230101_090000_initial_schema::Migration),
            Box::new(m20230102_090000_add_run_as_user::Migration),
            Box::new(m20230103_090000_add_signing_secret::Migration),
            Box::new(m20230104_090000_add_hmac_mode::Migration),
            Box::new(m20230105_090000_add_hook_soft_delete::Migration),
            Box::new(m20230106_090000_master_key_uniqueness::Migration),
            Box::new(m20230107_090000_key_lineage_and_resource_ownership::Migration),
            Box::new(m20260809_090000_add_can_view_execution::Migration),
            Box::new(m20260810_090000_drop_api_key_owner_key_id::Migration),
            Box::new(m20260819_120414_add_hook_auth_mode::Migration),
            Box::new(m20260819_141730_consolidate_hmac_modes::Migration),
        ]
    }
}
