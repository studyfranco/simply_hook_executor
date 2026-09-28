//! End-to-end coverage for `simply_hook_executor::ssh` against a real SSH server — the "mock/local
//! SSH execution" coverage this feature's test matrix calls for.
//!
//! No system `sshd` is involved: this spins up `russh::server` in-process on an ephemeral loopback
//! port, using the same `russh` crate the client side (`crate::ssh`) is built on. That is what makes
//! this fast and portable enough to run in ordinary `cargo test` rather than needing `#[ignore]` and
//! a host dependency — the daemon under test still exercises the real wire protocol (key exchange,
//! password/host-key auth negotiation, an `exec` channel, extended-data streaming, exit status), just
//! against a server this process itself controls instead of a copy of OpenSSH.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use russh::keys::{Algorithm, HashAlg, PrivateKey};
use russh::server::{self, Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use simply_hook_executor::crypto::SecretCipher;
use simply_hook_executor::entities::{execution::ExecutionStatus, ssh_credential, ssh_target};
use simply_hook_executor::executor::CommandPlan;
use simply_hook_executor::ssh::{self, SshConnectionSpec};
use uuid::Uuid;

/// A minimal SSH server: accepts exactly one password, accepts every channel/exec request, and
/// answers every `exec` with a fixed, recognizable stdout/stderr/exit-status triple — enough to
/// exercise every branch of `run_remote_process`'s message loop without needing a real shell on the
/// other end.
#[derive(Clone)]
struct TestServer {
    expected_password: Arc<str>,
}

impl server::Server for TestServer {
    type Handler = Self;

    fn new_client(&mut self, _peer_addr: Option<std::net::SocketAddr>) -> Self {
        self.clone()
    }
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == &*self.expected_password { Auth::Accept } else { Auth::reject() })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"hello-stdout\n".to_vec())?;
        session.extended_data(channel, 1, b"hello-stderr\n".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

/// Starts a [`TestServer`] on an ephemeral loopback port and returns `(port, host_key_fingerprint)`.
async fn spawn_test_server(expected_password: &str) -> (u16, String) {
    let host_key =
        PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).expect("Ed25519 key generation succeeds");
    let fingerprint = host_key.fingerprint(HashAlg::Sha256).to_string();

    let config = Arc::new(server::Config {
        // Real OpenSSH-scale rejection delays would make the auth-failure tests below needlessly
        // slow; this is a loopback test server, not a production target defending against timing
        // side channels.
        auth_rejection_time: Duration::from_millis(20),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });

    let listener =
        tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.expect("binds an ephemeral loopback port");
    let port = listener.local_addr().expect("a bound listener has a local address").port();

    let mut server = TestServer { expected_password: Arc::from(expected_password) };
    tokio::spawn(async move {
        // Errors here (e.g. the listener being dropped when the test's runtime shuts down) are
        // expected background noise once the owning test has finished with it, not a fatal test
        // failure — the assertions all happen against the client-side outcome instead.
        let _ = server.run_on_socket(config, &listener).await;
    });

    (port, fingerprint)
}

/// A `PASSWORD`-authenticated credential, sealed with `SecretCipher::Plaintext` (matching the rest of
/// this suite's convention of not exercising the encryption-at-rest question in the same tests as the
/// transport question — that is `crypto`'s own unit tests' job).
fn password_credential(password: &str) -> ssh_credential::Model {
    let now = Utc::now().naive_utc();
    ssh_credential::Model {
        id: Uuid::new_v4(),
        name: "test-credential".to_owned(),
        auth_type: ssh_credential::SshAuthType::Password,
        encrypted_private_key: None,
        encrypted_passphrase: None,
        encrypted_password: Some(SecretCipher::Plaintext.seal(password).expect("plaintext sealing never fails")),
        created_at: now,
        updated_at: now,
    }
}

fn target(credential_id: Uuid, port: u16, host_key_fingerprint: Option<&str>) -> ssh_target::Model {
    let now = Utc::now().naive_utc();
    ssh_target::Model {
        id: Uuid::new_v4(),
        name: "test-target".to_owned(),
        host: "127.0.0.1".to_owned(),
        port: i32::from(port),
        username: "testuser".to_owned(),
        credential_id,
        host_key_fingerprint: host_key_fingerprint.map(str::to_owned),
        created_at: now,
        updated_at: now,
    }
}

fn trivial_plan() -> CommandPlan {
    CommandPlan {
        program: "/usr/bin/true".to_owned(),
        args: Vec::new(),
        env: BTreeMap::new(),
        run_as_user: None,
    }
}

#[tokio::test]
async fn run_remote_process_captures_stdout_stderr_and_exit_status() {
    let (port, fingerprint) = spawn_test_server("correct-horse-battery-staple").await;
    let credential = password_credential("correct-horse-battery-staple");
    let target = target(credential.id, port, Some(&fingerprint));
    let spec = SshConnectionSpec::from_target_and_credential(&SecretCipher::Plaintext, &target, &credential)
        .expect("a fully-pinned target with a matching credential builds a spec");

    let outcome = ssh::run_remote_process(&spec, &trivial_plan(), Duration::from_secs(5), 64 * 1024).await;

    assert_eq!(outcome.status, ExecutionStatus::Success);
    assert_eq!(outcome.exit_code, Some(0));
    assert!(outcome.stdout.contains("hello-stdout"), "stdout was: {}", outcome.stdout);
    assert!(outcome.stderr.contains("hello-stderr"), "stderr was: {}", outcome.stderr);
}

#[tokio::test]
async fn run_remote_process_fails_closed_on_wrong_password() {
    let (port, fingerprint) = spawn_test_server("the-real-password").await;
    let credential = password_credential("a-completely-wrong-password");
    let target = target(credential.id, port, Some(&fingerprint));
    let spec = SshConnectionSpec::from_target_and_credential(&SecretCipher::Plaintext, &target, &credential)
        .expect("building a spec does not itself attempt authentication");

    let outcome = ssh::run_remote_process(&spec, &trivial_plan(), Duration::from_secs(5), 64 * 1024).await;

    assert_eq!(outcome.status, ExecutionStatus::Failed);
    assert!(outcome.exit_code.is_none());
    assert!(
        outcome.stderr.to_lowercase().contains("auth"),
        "expected an authentication failure message, got: {}",
        outcome.stderr
    );
}

#[tokio::test]
async fn run_remote_process_fails_closed_on_host_key_mismatch() {
    let (port, _real_fingerprint) = spawn_test_server("correct-horse-battery-staple").await;
    let credential = password_credential("correct-horse-battery-staple");
    // A well-formed but wrong fingerprint — this is the man-in-the-middle / rebuilt-host scenario
    // `HostKeyPinning` exists to refuse, not a malformed-input case.
    let wrong_fingerprint = "SHA256:0000000000000000000000000000000000000000A";
    let target = target(credential.id, port, Some(wrong_fingerprint));
    let spec = SshConnectionSpec::from_target_and_credential(&SecretCipher::Plaintext, &target, &credential)
        .expect("building a spec does not itself verify the host key");

    let outcome = ssh::run_remote_process(&spec, &trivial_plan(), Duration::from_secs(5), 64 * 1024).await;

    assert_eq!(outcome.status, ExecutionStatus::Failed);
    assert!(
        outcome.stderr.to_lowercase().contains("host key"),
        "expected a host-key mismatch message, got: {}",
        outcome.stderr
    );
}

#[tokio::test]
async fn run_remote_process_refuses_an_unpinned_target_without_connecting() {
    // `from_target_and_credential` itself refuses to build a spec at all — there is no connection
    // attempt to make, since `host_key_fingerprint` is `None`. Exercised here (rather than only in
    // `crate::ssh`'s own unit tests) to confirm the refusal happens *before* any network activity,
    // using a server this test would otherwise be able to reach successfully.
    let (port, _fingerprint) = spawn_test_server("correct-horse-battery-staple").await;
    let credential = password_credential("correct-horse-battery-staple");
    let target = target(credential.id, port, None);

    let result = SshConnectionSpec::from_target_and_credential(&SecretCipher::Plaintext, &target, &credential);
    assert!(result.is_err(), "an unpinned target must not yield a usable connection spec");
}

#[tokio::test]
async fn test_connection_reports_success_and_failure_as_data_not_errors() {
    let (port, fingerprint) = spawn_test_server("correct-horse-battery-staple").await;
    let credential = password_credential("correct-horse-battery-staple");
    let good_target = target(credential.id, port, Some(&fingerprint));
    let spec = SshConnectionSpec::from_target_and_credential(&SecretCipher::Plaintext, &good_target, &credential)
        .expect("spec builds");

    assert!(ssh::test_connection(&spec, Duration::from_secs(5)).await.is_ok());

    let wrong_credential = password_credential("not-the-password");
    let wrong_target = target(wrong_credential.id, port, Some(&fingerprint));
    let wrong_spec =
        SshConnectionSpec::from_target_and_credential(&SecretCipher::Plaintext, &wrong_target, &wrong_credential)
            .expect("spec builds even for a credential the server will reject");
    assert!(ssh::test_connection(&wrong_spec, Duration::from_secs(5)).await.is_err());
}

#[tokio::test]
async fn fetch_host_key_fingerprint_observes_the_servers_real_key() {
    let (port, fingerprint) = spawn_test_server("irrelevant-for-this-test").await;

    let observed = ssh::fetch_host_key_fingerprint("127.0.0.1", port, Duration::from_secs(5))
        .await
        .expect("a reachable server with a plain host key yields a fingerprint");

    assert_eq!(observed, fingerprint);
}
