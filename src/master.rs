//! Boot-time pinning of the Master key identity.
//!
//! # The attack this closes
//!
//! Every authorization decision in this service ultimately branches on `api_key::Model::is_master`,
//! and that value is read straight out of a database column on each request. An attacker who reaches
//! the database — a compromised backup restore, a misconfigured admin console, a second service
//! sharing the instance, an operator with a psql prompt — needs one `UPDATE` to become Master:
//!
//! ```sql
//! UPDATE api_keys SET is_master = true WHERE id = '<attacker key>';
//! ```
//!
//! `RBAC_MODEL.md` §5's uniqueness constraint refuses that statement, and this module exists because
//! a constraint is not a complete answer to it. A constraint can be dropped by the same access that
//! would run the `UPDATE`; it holds only while the schema is intact; and it says nothing about the
//! *running process*, which is where the authorization decisions are actually made.
//!
//! So the identity of the Master is resolved **once**, from a database whose invariants were checked
//! at that moment, and held in memory for the life of the process. After that, `is_master` on any
//! other row is inert: it is not consulted as authority, only noticed and logged. Restoring the flag
//! to something meaningful requires a restart, which is exactly the point — a restart is an event an
//! operator can see, and it re-runs the assertions below.
//!
//! # What this does not claim
//!
//! It is not a defence against an attacker who can write the database *and* restart the service, nor
//! against one who can edit `api_keys.key_hash` to point an existing Master row at a credential they
//! hold. Nothing at this layer could be. It closes the specific, cheap, and otherwise invisible
//! escalation of flipping a boolean on a row you already control.

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use sea_orm_migration::SchemaManager;
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::entities::{api_key, prelude::ApiKey};

/// The unique index `RBAC_MODEL.md` §5 requires over the engine-derived master marker.
///
/// Duplicated from the migration rather than imported so that module can stay private, and checked
/// by name at boot: a deployment whose index was dropped has lost the schema-level half of §5 and
/// should be told so at startup rather than at the moment somebody exploits it.
const MASTER_MARKER_INDEX: &str = "idx_api_keys_master_marker";

/// The table the index above belongs to.
const API_KEYS_TABLE: &str = "api_keys";

/// Why the Master identity could not be established at boot.
///
/// Every variant is fatal in production. They are distinguished because the operator response
/// differs sharply between them, and a single "startup failed" would leave someone guessing.
#[derive(Debug)]
pub enum MasterPinError {
    /// No key carries `is_master`. The service cannot be administered.
    ///
    /// Reachable only if the row was deleted directly in the database, since no endpoint can delete
    /// it. Recovery is the documented one: the bootstrap path re-mints on the next start, so this is
    /// a transient state between the delete and that restart — but it must not be *served* through,
    /// because a deployment with no Master silently accepts none of the master-only routes.
    NoMaster,
    /// More than one key carries `is_master`, so "the Master key" does not name anything.
    ///
    /// The §5 constraint makes this unreachable through any supported path. Seeing it means the
    /// constraint was absent or dropped while a second row was written, and picking a winner here
    /// would be this service inventing an answer to a question only an operator can settle.
    Duplicates(Vec<Uuid>),
    /// The §5 uniqueness index is missing from the schema.
    MissingConstraint,
    /// The database could not be queried at all.
    Db(sea_orm::DbErr),
}

impl std::fmt::Display for MasterPinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMaster => write!(
                f,
                "no key has is_master = true. The master row appears to have been deleted directly \
                 in the database; restart the service and the bootstrap path will re-mint it."
            ),
            Self::Duplicates(ids) => write!(
                f,
                "{} keys have is_master = true ({}), but RBAC_MODEL.md §5 requires exactly one. \
                 The uniqueness constraint is missing or was bypassed. Decide which key is the \
                 Master and demote the others with `UPDATE api_keys SET is_master = false WHERE id \
                 IN (...);`, then restart. This service will not choose for you.",
                ids.len(),
                ids.iter().map(Uuid::to_string).collect::<Vec<_>>().join(", ")
            ),
            Self::MissingConstraint => write!(
                f,
                "the unique index '{MASTER_MARKER_INDEX}' is missing from '{API_KEYS_TABLE}'. \
                 RBAC_MODEL.md §5 requires master uniqueness to be enforced by the database rather \
                 than by application logic alone. Re-run migrations."
            ),
            Self::Db(e) => write!(f, "could not query the database to establish the master key: {e}"),
        }
    }
}

impl std::error::Error for MasterPinError {}

impl From<sea_orm::DbErr> for MasterPinError {
    fn from(e: sea_orm::DbErr) -> Self {
        Self::Db(e)
    }
}

/// The pinned Master key id, resolved once per process.
///
/// # Why a `OnceCell` rather than a plain `Uuid` on [`crate::state::AppState`]
///
/// Two callers need this and they arrive at different times. Production resolves it during startup,
/// before the listener binds, via [`Self::pin_at_boot`] — which additionally asserts §5's invariants
/// and refuses to start when they do not hold. Tests build their state first and seed keys
/// afterwards, so for them the value is resolved on first use.
///
/// Both paths run **the same resolution**, and both are equally sticky: once a value is stored it is
/// never replaced. That matters more than the timing. If the two differed — a lazily-resolved test
/// build and a boot-pinned production build — then the property under test would not be the property
/// deployed, and the guard would be exercised by nothing.
///
/// Resolution stores a value **only when exactly one Master exists**. A database with none, or with
/// several, leaves the cell empty, which means [`Self::authenticate`] treats every key as non-master
/// until the ambiguity is resolved and the process restarted. That is the conservative direction:
/// the failure mode is "nobody is Master", never "the wrong key is Master".
#[derive(Debug, Default)]
pub struct MasterPin {
    cell: OnceCell<Uuid>,
}

impl MasterPin {
    /// An unresolved pin.
    pub fn new() -> Self {
        Self { cell: OnceCell::new() }
    }

    /// A pin fixed to a known id, without consulting the database.
    ///
    /// For tests that need to assert the *negative*: what a key does when it claims mastery and is
    /// not the pinned identity. Building that situation through [`Self::resolve`] is impossible by
    /// construction, because resolution only ever pins a row that really is the sole Master.
    pub fn pinned_to(id: Uuid) -> Self {
        let cell = OnceCell::new();
        cell.set(id).expect("a fresh cell is empty");
        Self { cell }
    }

    /// The pinned id, if one has been established.
    pub fn get(&self) -> Option<Uuid> {
        self.cell.get().copied()
    }

    /// Establishes the Master identity at startup, asserting every §5 invariant on the way.
    ///
    /// Production calls this before binding the listener. It is deliberately noisy and deliberately
    /// fatal: each error it returns describes a database that cannot be served safely, and serving
    /// anyway would mean running with authorization decisions nobody has checked.
    pub async fn pin_at_boot(&self, db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        // The schema-level guarantee first. If the index is gone, the count below proves nothing
        // about the future — a second master could be written a millisecond later.
        let manager = SchemaManager::new(db);
        if !manager.has_index(API_KEYS_TABLE, MASTER_MARKER_INDEX).await? {
            return Err(MasterPinError::MissingConstraint);
        }

        let id = self.resolve_inner(db).await?;
        // `set` fails only if something resolved first, which in production cannot happen — nothing
        // serves requests before this runs. Tolerated rather than asserted so a test that primed the
        // pin can still call this without tripping over itself.
        let _ = self.cell.set(id);

        let pinned = self.cell.get().copied().unwrap_or(id);
        tracing::info!(
            master_key_id = %pinned,
            "Master key identity pinned for the lifetime of this process. is_master on any other \
             row will be ignored until restart."
        );
        Ok(pinned)
    }

    /// The pinned id, resolving it from the database on first use.
    ///
    /// Returns `None` when the database does not contain exactly one Master, leaving the pin unset
    /// so a later call can still succeed once an operator has fixed the row.
    pub async fn resolve(&self, db: &DatabaseConnection) -> Option<Uuid> {
        if let Some(id) = self.cell.get() {
            return Some(*id);
        }
        match self.resolve_inner(db).await {
            Ok(id) => {
                let _ = self.cell.set(id);
                self.cell.get().copied()
            }
            Err(e) => {
                tracing::warn!("Master key identity is not established: {e}");
                None
            }
        }
    }

    /// Reads the sole Master row, or explains why there isn't one.
    async fn resolve_inner(&self, db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        let masters = ApiKey::find()
            .filter(api_key::Column::IsMaster.eq(true))
            .all(db)
            .await?;

        match masters.len() {
            0 => Err(MasterPinError::NoMaster),
            1 => Ok(masters[0].id),
            _ => Err(MasterPinError::Duplicates(masters.iter().map(|k| k.id).collect())),
        }
    }

    /// Applies the pin to a freshly authenticated key record.
    ///
    /// This is the **single choke point** for the whole guarantee, and it is a mutation of the
    /// principal rather than a check sprinkled through the handlers. That is the entire design: there
    /// are dozens of `key.is_master` reads across `api.rs`, and any scheme requiring each of them to
    /// also compare an id would be one forgotten call site away from being worthless — including
    /// every call site added later, by someone who never read this module.
    ///
    /// Instead the record handed to handlers is the *effective* principal. Downstream code keeps
    /// reading `key.is_master` and is automatically correct, because a key that is not the pinned
    /// Master no longer says it is.
    ///
    /// A demotion is logged at `error` level. It has exactly one cause — a row claiming mastery that
    /// was not the Master when this process started — and there is no benign explanation for it.
    pub async fn authenticate(&self, db: &DatabaseConnection, key: &mut api_key::Model) {
        if !key.is_master {
            return;
        }

        match self.resolve(db).await {
            Some(pinned) if pinned == key.id => {}
            Some(pinned) => {
                tracing::error!(
                    key = %key.prefix,
                    claimed_id = %key.id,
                    pinned_master = %pinned,
                    "TAMPER: a key carries is_master = true but is not the master this process \
                     pinned at boot. Treating it as an ordinary key. Someone has written to \
                     api_keys directly."
                );
                key.is_master = false;
            }
            None => {
                tracing::error!(
                    key = %key.prefix,
                    claimed_id = %key.id,
                    "A key carries is_master = true but this process has no pinned master \
                     (the database does not contain exactly one). Treating it as an ordinary key."
                );
                key.is_master = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_cell_reports_its_id_without_a_database() {
        let id = Uuid::new_v4();
        let pin = MasterPin::pinned_to(id);
        assert_eq!(pin.get(), Some(id));
    }

    #[test]
    fn a_fresh_pin_is_unresolved() {
        assert_eq!(MasterPin::new().get(), None);
    }

    /// The error text is operator-facing and names the remedy; a bare "startup failed" would not.
    #[test]
    fn every_failure_explains_what_to_do_about_it() {
        assert!(MasterPinError::NoMaster.to_string().contains("restart"));

        let dupes = MasterPinError::Duplicates(vec![Uuid::nil(), Uuid::max()]);
        let text = dupes.to_string();
        assert!(text.contains("UPDATE api_keys SET is_master = false"));
        assert!(text.contains(&Uuid::nil().to_string()), "the offending ids are named: {text}");
        assert!(text.contains("will not choose for you"));

        assert!(MasterPinError::MissingConstraint.to_string().contains(MASTER_MARKER_INDEX));
    }
}
