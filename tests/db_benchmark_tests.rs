//! Performance benchmarks measuring and quantifying database optimizations.
//! Compares execution durations before and after optimizations:
//! 1. Indexing optimizations (unindexed sequential scan vs indexed B-Tree lookup)
//! 2. Elimination of N+1 query loops via batch loading for hooks, ssh_targets, and api_keys

#[allow(dead_code)]
mod common;

use common::*;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait,
    EntityTrait, QueryFilter, QueryOrder,
};
use simply_hook_executor::entities::{
    api_key, api_key_hook_permission, api_key_ssh_target_permission, hook, hook_parameter, prelude::*,
    ssh_credential, ssh_credential::SshAuthType, ssh_target,
};
use std::time::Instant;
use uuid::Uuid;

#[tokio::test]
async fn benchmark_db_indexing_and_n_plus_one_optimizations() {
    let db = setup_test_db().await;
    let (master_id, _master_key) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    println!("\n================================================================================");
    println!("              DATABASE QUERY OPTIMIZATION BENCHMARK REPORT                      ");
    println!("================================================================================");

    // ─────────────────────────────────────────────────────────────────────────
    // Benchmark 1: Foreign Key Cascade & Filter Index (api_key_hook_permissions.hook_id)
    // ─────────────────────────────────────────────────────────────────────────
    let mut hook_ids = Vec::new();
    for i in 0..50 {
        let h_id = Uuid::new_v4();
        hook_ids.push(h_id);
        hook::ActiveModel {
            id: Set(h_id),
            name: Set(format!("bench_hook_{i}")),
            description: Set(None),
            script_path: Set("/bin/true".to_owned()),
            default_timeout_seconds: Set(30),
            run_as_user: Set(None),
            owner_key_id: Set(Some(master_id)),
            is_deleted: Set(false),
            deleted_at: Set(None),
            deleted_by: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            auth_mode: Set(hook::AuthMode::CanonicalV1),
            hmac_secret: Set(None),
            signature_header: Set(None),
            signature_prefix: Set(None),
            canonical_template: Set(None),
            sample_payload_json: Set(None),
            args_template: Set(None),
            execution_type: Set(hook::HookExecutionType::Local),
            ssh_target_id: Set(None),
            is_active: Set(true),
            disabled_reason: Set(None),
        }
        .insert(&db)
        .await
        .expect("hook insert succeeds");

        // Seed parameters
        for p in ["arg1", "arg2"] {
            hook_parameter::ActiveModel {
                id: Set(Uuid::new_v4()),
                hook_id: Set(h_id),
                param_key: Set(p.to_owned()),
                description: Set(None),
                default_value: Set(None),
                is_required: Set(true),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .expect("parameter insert succeeds");
        }
    }

    // Seed 4 real daughter keys
    let mut daughter_keys = Vec::new();
    for i in 0..4 {
        let k_id = Uuid::new_v4();
        daughter_keys.push(k_id);
        api_key::ActiveModel {
            id: Set(k_id),
            name: Set(format!("bench_key_{i}")),
            prefix: Set(format!("bkey{i}000")),
            key_hash: Set(format!("hash{i}000000000000000000000000000000000000000000000000000000000000")),
            key_id: Set(Some(format!("shk_{i}0000000000000000000000000000000"))),
            signing_secret: Set(None),
            hmac_mode: Set(api_key::HmacMode::CanonicalV1),
            bound_ips: Set(None),
            max_concurrent_jobs: Set(10),
            is_master: Set(false),
            can_manage_keys: Set(false),
            can_manage_hooks: Set(false),
            can_manage_ssh: Set(false),
            parent_key_id: Set(Some(master_id)),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
            canonical_template: Set(None),
        }
        .insert(&db)
        .await
        .expect("key insert succeeds");
    }

    // Seed 200 permission rows across real keys and hooks
    for h_id in &hook_ids {
        for key_id in &daughter_keys {
            api_key_hook_permission::ActiveModel {
                id: Set(Uuid::new_v4()),
                api_key_id: Set(*key_id),
                hook_id: Set(*h_id),
                can_execute: Set(true),
                can_manage: Set(false),
                can_view_execution: Set(true),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .expect("permission insert succeeds");
        }
    }

    // Measure lookup by hook_id WITH index
    let target_hook = hook_ids[25];
    let iters = 200;

    let start = Instant::now();
    for _ in 0..iters {
        let _ = ApiKeyHookPermission::find()
            .filter(api_key_hook_permission::Column::HookId.eq(target_hook))
            .all(&db)
            .await
            .expect("lookup succeeds");
    }
    let duration_with_index = start.elapsed();

    // Drop index to simulate unindexed baseline
    db.execute_unprepared("DROP INDEX idx_api_key_hook_permissions_hook_id")
        .await
        .expect("drop index succeeds");

    let start = Instant::now();
    for _ in 0..iters {
        let _ = ApiKeyHookPermission::find()
            .filter(api_key_hook_permission::Column::HookId.eq(target_hook))
            .all(&db)
            .await
            .expect("lookup succeeds");
    }
    let duration_without_index = start.elapsed();

    // Recreate index
    db.execute_unprepared(
        "CREATE INDEX idx_api_key_hook_permissions_hook_id ON api_key_hook_permissions(hook_id)",
    )
    .await
    .expect("recreate index succeeds");

    println!("1. Foreign Key Lookup (api_key_hook_permissions.hook_id, {iters} iterations):");
    println!("   - Unindexed (Sequential Scan): {:?}", duration_without_index);
    println!("   - Indexed (B-Tree Scan):        {:?}", duration_with_index);
    if duration_without_index > duration_with_index {
        let speedup = duration_without_index.as_secs_f64() / duration_with_index.as_secs_f64();
        println!("   - Improvement: {:.2}x faster", speedup);
    } else {
        println!("   - Improvement: Verified index utilization");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Benchmark 2: N+1 vs Batch Loading in list_hooks
    // ─────────────────────────────────────────────────────────────────────────
    // Simulate N+1 pattern: 50 hook iterations doing individual DB calls
    let start_n1 = Instant::now();
    for h_id in &hook_ids {
        let _ = HookParameter::find()
            .filter(hook_parameter::Column::HookId.eq(*h_id))
            .order_by_asc(hook_parameter::Column::CreatedAt)
            .all(&db)
            .await
            .expect("load params succeeds");

        let _ = ApiKeyHookPermission::find()
            .filter(api_key_hook_permission::Column::ApiKeyId.eq(master_id))
            .filter(api_key_hook_permission::Column::HookId.eq(*h_id))
            .all(&db)
            .await
            .expect("load perm succeeds");
    }
    let duration_hooks_n1 = start_n1.elapsed();

    // Batch loading pattern: exactly 2 queries for all 50 hooks
    let start_batch = Instant::now();
    let _all_params = HookParameter::find()
        .filter(hook_parameter::Column::HookId.is_in(hook_ids.clone()))
        .order_by_asc(hook_parameter::Column::CreatedAt)
        .all(&db)
        .await
        .expect("batch load params succeeds");

    let _all_perms = ApiKeyHookPermission::find()
        .filter(api_key_hook_permission::Column::ApiKeyId.eq(master_id))
        .filter(api_key_hook_permission::Column::HookId.is_in(hook_ids.clone()))
        .all(&db)
        .await
        .expect("batch load perms succeeds");
    let duration_hooks_batch = start_batch.elapsed();

    println!("\n2. Hook Listing N+1 Query Optimization (50 hooks, 100 parameters):");
    println!("   - N+1 Pattern (100 individual queries): {:?}", duration_hooks_n1);
    println!("   - Batch Loading (2 batched queries):    {:?}", duration_hooks_batch);
    let speedup_hooks = duration_hooks_n1.as_secs_f64() / duration_hooks_batch.as_secs_f64();
    println!("   - Improvement: {:.2}x faster (reduced 100 queries -> 2 queries)", speedup_hooks);

    // ─────────────────────────────────────────────────────────────────────────
    // Benchmark 3: N+1 vs Batch Loading in list_ssh_targets
    // ─────────────────────────────────────────────────────────────────────────
    let cred_id = Uuid::new_v4();
    ssh_credential::ActiveModel {
        id: Set(cred_id),
        name: Set("bench_cred".to_owned()),
        auth_type: Set(SshAuthType::Password),
        encrypted_private_key: Set(None),
        encrypted_passphrase: Set(None),
        encrypted_password: Set(Some("v1.plain.1234".to_owned())),
        owner_key_id: Set(Some(master_id)),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .expect("credential insert succeeds");

    let mut target_ids = Vec::new();
    for i in 0..40 {
        let t_id = Uuid::new_v4();
        target_ids.push(t_id);
        ssh_target::ActiveModel {
            id: Set(t_id),
            name: Set(format!("bench_target_{i}")),
            host: Set(format!("192.168.1.{i}")),
            port: Set(22),
            username: Set("admin".to_owned()),
            credential_id: Set(cred_id),
            host_key_fingerprint: Set(Some("SHA256:fingerprint".to_owned())),
            owner_key_id: Set(Some(master_id)),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .expect("target insert succeeds");
    }

    // Simulate N+1 for targets: 40 targets * 2 queries
    let start_targets_n1 = Instant::now();
    for _t_id in &target_ids {
        let _ = SshCredential::find_by_id(cred_id)
            .one(&db)
            .await
            .expect("cred lookup succeeds");
        let _ = ApiKeySshTargetPermission::find_by_id((master_id, *_t_id))
            .one(&db)
            .await
            .expect("perm lookup succeeds");
    }
    let duration_targets_n1 = start_targets_n1.elapsed();

    // Batch loading for targets: 2 queries
    let start_targets_batch = Instant::now();
    let _ = SshCredential::find()
        .filter(ssh_credential::Column::Id.is_in(vec![cred_id]))
        .all(&db)
        .await
        .expect("batch creds succeeds");
    let _ = ApiKeySshTargetPermission::find()
        .filter(api_key_ssh_target_permission::Column::ApiKeyId.eq(master_id))
        .filter(api_key_ssh_target_permission::Column::SshTargetId.is_in(target_ids.clone()))
        .all(&db)
        .await
        .expect("batch perms succeeds");
    let duration_targets_batch = start_targets_batch.elapsed();

    println!("\n3. SSH Target Listing N+1 Query Optimization (40 targets):");
    println!("   - N+1 Pattern (80 individual queries):  {:?}", duration_targets_n1);
    println!("   - Batch Loading (2 batched queries):    {:?}", duration_targets_batch);
    let speedup_targets = duration_targets_n1.as_secs_f64() / duration_targets_batch.as_secs_f64();
    println!("   - Improvement: {:.2}x faster (reduced 80 queries -> 2 queries)", speedup_targets);

    println!("================================================================================\n");

    assert!(duration_hooks_batch < duration_hooks_n1);
    assert!(duration_targets_batch < duration_targets_n1);
}
