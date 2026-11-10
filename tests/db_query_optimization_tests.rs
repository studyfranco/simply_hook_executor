//! Tests validating database indexes, query optimization, and batching.

#[allow(dead_code)]
mod common;

use axum::http::StatusCode;
use common::*;
use sea_orm::{ActiveModelTrait, ActiveValue::Set};
use sea_orm_migration::SchemaManager;
use simply_hook_executor::{
    create_app,
    entities::{
        api_key, api_key_hook_permission, hook, hook_parameter, ssh_credential,
        ssh_credential::SshAuthType, ssh_target,
    },
};
use uuid::Uuid;

#[tokio::test]
async fn all_performance_and_foreign_key_indexes_exist() {
    let db = setup_test_db().await;
    let manager = SchemaManager::new(&db);

    let expected_indexes = [
        ("api_key_hook_permissions", "idx_api_key_hook_permissions_hook_id"),
        ("api_key_ssh_target_permissions", "idx_api_key_ssh_target_permissions_ssh_target_id"),
        ("ssh_credentials", "idx_ssh_credentials_owner_key_id"),
        ("ssh_credentials", "idx_ssh_credentials_created_at"),
        ("ssh_targets", "idx_ssh_targets_owner_key_id"),
        ("ssh_targets", "idx_ssh_targets_created_at"),
        ("api_keys", "idx_api_keys_name"),
        ("api_keys", "idx_api_keys_created_at"),
        ("hooks", "idx_hooks_is_deleted_name"),
        ("hooks", "idx_hooks_deleted_at"),
        ("hooks", "idx_hooks_is_active"),
        ("hooks", "idx_hooks_created_at"),
        ("audit_logs", "idx_audit_logs_target_resource"),
    ];

    for (table, index) in expected_indexes {
        assert!(
            manager
                .has_index(table, index)
                .await
                .expect("index check succeeds"),
            "Expected index {index} on table {table} does not exist"
        );
    }
}

#[tokio::test]
async fn list_hooks_batch_loads_parameters_and_permissions() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (master_id, master_key) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    // Seed multiple hooks with multiple parameters
    for i in 0..5 {
        let hook_id = Uuid::new_v4();
        let hook_name = format!("hook_batch_{i}");
        hook::ActiveModel {
            id: Set(hook_id),
            name: Set(hook_name),
            description: Set(Some("test description".to_owned())),
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

        // Add 2 parameters per hook
        for p in ["param_a", "param_b"] {
            hook_parameter::ActiveModel {
                id: Set(Uuid::new_v4()),
                hook_id: Set(hook_id),
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

    // Call GET /api/hooks as master
    let resp = send(&app, json_request("GET", "/api/hooks", &master_key, None)).await;
    assert_eq!(resp.status, StatusCode::OK);

    let hooks = resp.json.as_array().expect("array response");
    assert_eq!(hooks.len(), 5);
    for h in hooks {
        let params = h["parameters"].as_array().expect("parameters array");
        assert_eq!(params.len(), 2);
        assert_eq!(h["can_execute"], true);
        assert_eq!(h["can_manage"], true);
    }
}

#[tokio::test]
async fn list_ssh_targets_batch_loads_credentials_and_permissions() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (master_id, master_key) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    // Seed credential
    let cred_id = Uuid::new_v4();
    ssh_credential::ActiveModel {
        id: Set(cred_id),
        name: Set("cred-test-batch".to_owned()),
        auth_type: Set(SshAuthType::Password),
        encrypted_private_key: Set(None),
        encrypted_passphrase: Set(None),
        encrypted_password: Set(Some("v1.plain.74657374".to_owned())),
        owner_key_id: Set(Some(master_id)),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .expect("credential insert succeeds");

    // Seed 3 targets using this credential
    for i in 0..3 {
        ssh_target::ActiveModel {
            id: Set(Uuid::new_v4()),
            name: Set(format!("target-batch-{i}")),
            host: Set(format!("10.0.0.{i}")),
            port: Set(22),
            username: Set("admin".to_owned()),
            credential_id: Set(cred_id),
            host_key_fingerprint: Set(Some("SHA256:dGVzdA".to_owned())),
            owner_key_id: Set(Some(master_id)),
            created_at: Set(chrono::Utc::now().naive_utc()),
            updated_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .expect("target insert succeeds");
    }

    // Call GET /api/ssh-targets as master
    let resp = send(&app, json_request("GET", "/api/ssh-targets", &master_key, None)).await;
    assert_eq!(resp.status, StatusCode::OK);

    let targets = resp.json.as_array().expect("array response");
    assert_eq!(targets.len(), 3);
    for t in targets {
        assert_eq!(t["credential_name"], "cred-test-batch");
        assert_eq!(t["is_owner"], true);
        assert_eq!(t["can_use_in_hook"], true);
    }
}

#[tokio::test]
async fn list_api_keys_batch_loads_permissions() {
    let db = setup_test_db().await;
    let app = create_app(test_state(&db));
    let (master_id, master_key) = insert_key(&db, "master", "0.0.0.0/0", KeyScopes::master()).await;

    // Seed a hook
    let hook_id = Uuid::new_v4();
    hook::ActiveModel {
        id: Set(hook_id),
        name: Set("key_test_hook".to_owned()),
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

    // Seed 2 daughter keys with permissions on that hook
    for i in 0..2 {
        let key_id = Uuid::new_v4();
        api_key::ActiveModel {
            id: Set(key_id),
            name: Set(format!("daughter_key_{i}")),
            prefix: Set(format!("dkey{i}000")),
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

        api_key_hook_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(key_id),
            hook_id: Set(hook_id),
            can_execute: Set(true),
            can_manage: Set(false),
            can_view_execution: Set(true),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .expect("permission insert succeeds");
    }

    let resp = send(&app, json_request("GET", "/api/keys", &master_key, None)).await;
    assert_eq!(resp.status, StatusCode::OK);

    let keys = resp.json.as_array().expect("array response");
    assert_eq!(keys.len(), 3); // 1 master + 2 daughters

    for k in keys {
        let name = k["name"].as_str().unwrap();
        if name.starts_with("daughter_key_") {
            let perms = k["hook_permissions"].as_array().expect("permissions array");
            assert_eq!(perms.len(), 1);
            assert_eq!(perms[0]["hook_name"], "key_test_hook");
            assert_eq!(perms[0]["can_execute"], true);
            assert_eq!(perms[0]["can_view_execution"], true);
        }
    }
}
