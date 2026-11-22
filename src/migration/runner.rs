use std::collections::BTreeSet;

use sea_orm::sea_query::{
    IndexCreateStatement, IndexDropStatement, SelectStatement, TableAlterStatement,
    TableCreateStatement, TableDropStatement,
};
use sea_orm::{
    ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr, EntityTrait,
    Schema, Set, StatementBuilder, TransactionTrait,
};
use sea_schema::probe::SchemaProbe;

pub(super) mod prelude {
    pub(in crate::migration) use super::migration_name;
    pub use super::{MigrationTrait, SchemaManager};
    pub use sea_orm::sea_query::{
        ColumnDef, Expr, ExprTrait, ForeignKey, ForeignKeyAction, Index, IndexOrder, IntoIden,
        Query, Table, TableAlterStatement,
    };
    pub use sea_orm::{DbErr, DeriveIden};
}

macro_rules! migration_name {
    ($migration:ty) => {
        impl $crate::migration::MigrationName for $migration {
            fn name(&self) -> &str {
                module_path!().rsplit("::").next().unwrap_or(module_path!())
            }
        }
    };
}
pub(super) use migration_name;

mod history {
    use sea_orm::entity::prelude::*;

    // This is the existing migration ledger, including the original primary key type.
    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "seaql_migrations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub version: String,
        pub applied_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Stable ledger identifier derived from the migration module name.
pub trait MigrationName {
    /// Returns the migration version recorded in the ledger.
    fn name(&self) -> &str;
}

/// One versioned schema change.
#[async_trait::async_trait]
pub trait MigrationTrait: MigrationName + Send + Sync {
    /// Applies this schema change.
    ///
    /// # Errors
    /// Returns any database error from the change.
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr>;

    /// Reverts this schema change.
    ///
    /// # Errors
    /// Returns any database error from the change.
    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr>;
}

enum Connection<'a> {
    Pool(&'a DatabaseConnection),
    Transaction(&'a DatabaseTransaction),
}

/// Executes typed schema statements and inspects the active database schema.
pub struct SchemaManager<'a>(Connection<'a>);

impl<'a> SchemaManager<'a> {
    /// Creates a manager backed by an existing pool.
    #[must_use]
    pub fn new(db: &'a DatabaseConnection) -> Self {
        Self(Connection::Pool(db))
    }

    /// Returns the dialect used by the underlying connection.
    #[must_use]
    pub fn get_database_backend(&self) -> DatabaseBackend {
        match self.0 {
            Connection::Pool(db) => db.get_database_backend(),
            Connection::Transaction(db) => db.get_database_backend(),
        }
    }

    /// Executes a typed statement.
    ///
    /// # Errors
    /// Returns an error if execution fails.
    pub async fn execute(&self, stmt: impl StatementBuilder) -> Result<(), DbErr> {
        match self.0 {
            Connection::Pool(db) => db.execute(&stmt).await?,
            Connection::Transaction(db) => db.execute(&stmt).await?,
        };
        Ok(())
    }

    async fn probe(&self, stmt: &SelectStatement, alias: &str) -> Result<bool, DbErr> {
        let row = match self.0 {
            Connection::Pool(db) => db.query_one(stmt).await?,
            Connection::Transaction(db) => db.query_one(stmt).await?,
        };
        row.ok_or_else(|| DbErr::Migration(format!("Schema probe returned no result for {alias}")))?
            .try_get("", alias)
    }

    /// Runs a table create statement.
    ///
    /// # Errors
    /// Returns an error if the statement fails.
    pub async fn create_table(&self, stmt: TableCreateStatement) -> Result<(), DbErr> {
        self.execute(stmt).await
    }

    /// Runs a table alter statement.
    ///
    /// # Errors
    /// Returns an error if the statement fails.
    pub async fn alter_table(&self, stmt: TableAlterStatement) -> Result<(), DbErr> {
        self.execute(stmt).await
    }

    /// Runs a table drop statement.
    ///
    /// # Errors
    /// Returns an error if the statement fails.
    pub async fn drop_table(&self, stmt: TableDropStatement) -> Result<(), DbErr> {
        self.execute(stmt).await
    }

    /// Runs a index create statement.
    ///
    /// # Errors
    /// Returns an error if the statement fails.
    pub async fn create_index(&self, stmt: IndexCreateStatement) -> Result<(), DbErr> {
        self.execute(stmt).await
    }

    /// Runs a index drop statement.
    ///
    /// # Errors
    /// Returns an error if the statement fails.
    pub async fn drop_index(&self, stmt: IndexDropStatement) -> Result<(), DbErr> {
        self.execute(stmt).await
    }

    /// Checks whether the table exists in the active schema.
    ///
    /// # Errors
    /// Returns an error if the schema probe fails.
    pub async fn has_table(&self, table: &str) -> Result<bool, DbErr> {
        let stmt = match self.get_database_backend() {
            DatabaseBackend::MySql => sea_schema::mysql::MySql.has_table(table),
            DatabaseBackend::Postgres => sea_schema::postgres::Postgres.has_table(table),
            DatabaseBackend::Sqlite => sea_schema::sqlite::Sqlite.has_table(table),
            backend => {
                return Err(DbErr::BackendNotSupported {
                    db: backend.as_str(),
                    ctx: "has_table",
                });
            }
        };
        self.probe(&stmt, "has_table").await
    }

    /// Checks whether the column exists in the active schema.
    ///
    /// # Errors
    /// Returns an error if the schema probe fails.
    pub async fn has_column(&self, table: &str, column: &str) -> Result<bool, DbErr> {
        let stmt = match self.get_database_backend() {
            DatabaseBackend::MySql => sea_schema::mysql::MySql.has_column(table, column),
            DatabaseBackend::Postgres => sea_schema::postgres::Postgres.has_column(table, column),
            DatabaseBackend::Sqlite => sea_schema::sqlite::Sqlite.has_column(table, column),
            backend => {
                return Err(DbErr::BackendNotSupported {
                    db: backend.as_str(),
                    ctx: "has_column",
                });
            }
        };
        self.probe(&stmt, "has_column").await
    }

    /// Checks whether the index exists in the active schema.
    ///
    /// # Errors
    /// Returns an error if the schema probe fails.
    pub async fn has_index(&self, table: &str, index: &str) -> Result<bool, DbErr> {
        let stmt = match self.get_database_backend() {
            DatabaseBackend::MySql => sea_schema::mysql::MySql.has_index(table, index),
            DatabaseBackend::Postgres => sea_schema::postgres::Postgres.has_index(table, index),
            DatabaseBackend::Sqlite => sea_schema::sqlite::Sqlite.has_index(table, index),
            backend => {
                return Err(DbErr::BackendNotSupported {
                    db: backend.as_str(),
                    ctx: "has_index",
                });
            }
        };
        self.probe(&stmt, "has_index").await
    }
}

/// Applies ordered migrations and records their versions in the existing ledger.
#[async_trait::async_trait]
pub trait MigratorTrait {
    /// Returns all migrations in application order.
    fn migrations() -> Vec<Box<dyn MigrationTrait>>;

    /// Applies pending migrations, optionally stopping after `steps` new versions.
    ///
    /// # Errors
    /// Returns an error for an unrecognized applied version or if a migration fails.
    async fn up(db: &DatabaseConnection, steps: Option<u32>) -> Result<(), DbErr>;
}

pub(super) async fn apply_migrations(
    migrations: Vec<Box<dyn MigrationTrait>>,
    db: &DatabaseConnection,
    steps: Option<u32>,
) -> Result<(), DbErr> {
    let mut table =
        Schema::new(db.get_database_backend()).create_table_from_entity(history::Entity);
    db.execute(table.if_not_exists()).await?;

    let applied: BTreeSet<_> = history::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.version)
        .collect();
    for version in &applied {
        if !migrations
            .iter()
            .any(|migration| migration.name() == version)
        {
            return Err(DbErr::Migration(format!(
                "Applied migration {version} is missing from the registry"
            )));
        }
    }

    let pending = migrations
        .into_iter()
        .filter(|migration| !applied.contains(migration.name()))
        .take(steps.map_or(usize::MAX, |count| count as usize));
    for migration in pending {
        let version = migration.name();
        tracing::info!(version, "Applying database migration");
        let row = history::ActiveModel {
            version: Set(version.to_owned()),
            applied_at: Set(time::OffsetDateTime::now_utc().unix_timestamp()),
        };
        // MySQL implicitly commits DDL. SQLite and PostgreSQL can record the
        // migration atomically with the schema changes.
        if db.get_database_backend() == DatabaseBackend::MySql {
            migration.up(&SchemaManager::new(db)).await?;
            history::Entity::insert(row).exec(db).await?;
        } else {
            let transaction = db.begin().await?;
            let manager = SchemaManager(Connection::Transaction(&transaction));
            migration.up(&manager).await?;
            history::Entity::insert(row).exec(&transaction).await?;
            transaction.commit().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::Migrator;
    use sea_orm::sea_query::{Alias, ColumnDef, Query, Table};

    #[tokio::test]
    async fn legacy_migration_ledger_is_reused() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let ledger = Alias::new("seaql_migrations");
        let version = Alias::new("version");
        let applied_at = Alias::new("applied_at");
        db.execute(
            Table::create()
                .table(ledger.clone())
                .col(
                    ColumnDef::new(version.clone())
                        .string()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(applied_at.clone()).big_integer().not_null()),
        )
        .await
        .unwrap();

        let migrations = Migrator::migrations();
        let initial = &migrations[0];
        let initial_version = "m20230101_090000_initial_schema";
        let next_version = "m20230102_090000_add_run_as_user";
        assert_eq!(initial.name(), initial_version);
        let manager = SchemaManager::new(&db);
        initial.up(&manager).await.unwrap();
        db.execute(
            Query::insert()
                .into_table(ledger)
                .columns([version, applied_at])
                .values_panic([initial_version.into(), 123_i64.into()]),
        )
        .await
        .unwrap();

        assert!(!manager.has_column("hooks", "run_as_user").await.unwrap());
        Migrator::up(&db, Some(1)).await.unwrap();
        assert!(manager.has_column("hooks", "run_as_user").await.unwrap());
        let original = history::Entity::find_by_id(initial_version)
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(original.applied_at, 123);
        assert!(
            history::Entity::find_by_id(next_version)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );

        Migrator::up(&db, None).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let rows = history::Entity::find().all(&db).await.unwrap();
        let applied: BTreeSet<_> = rows.iter().map(|row| row.version.as_str()).collect();
        assert_eq!(
            applied,
            migrations
                .iter()
                .map(|migration| migration.name())
                .collect()
        );
    }
}
