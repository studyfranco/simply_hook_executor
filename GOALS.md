# Simply Hook Executor goals

Simply Hook Executor is a self-hosted API and dashboard that turns authorized
webhooks into runs of operator-configured scripts on the local machine or over SSH.

## Core goals

- Let internal services trigger repeatable operational tasks through a small HTTP interface.
- Scope access to hooks, SSH targets, and execution history. Support signed requests and record
  configuration changes in the audit trail.
- Keep deployment small with a single daemon, a built-in dashboard, and SQLite by default.
  Keep the storage layer portable across SQLite, PostgreSQL, and MySQL.

## Non-goals

- Interactive remote access or caller-supplied commands and scripts.
- Workflow orchestration across multiple machines or jobs.
- Sandboxing the code inside a configured script. Operators own the scripts and the privileges
  of the accounts that run them.

## Execution boundary

Local execution uses no shell. The daemon passes an argument vector directly to the configured executable.
The daemon clears the inherited environment and passes only allowlisted variables and
hook parameters. It resolves the executable path and checks containment under configured
script roots when path restrictions are enabled. On Unix, process-group isolation allows
the timeout to terminate the local process group, including child processes.

SSH execution uses a configured target, credential, account, and script path. The daemon
pins the server host key by its stored fingerprint before authentication. SSH servers normally
process exec requests through the remote account's shell. The daemon quotes the script path
and each argument as a literal. Operators enforce remote path and account restrictions on
the SSH server. The daemon bounds the SSH session, while remote process cleanup depends on
the server and the script.

## Network placement

- Attach the executor to `isolate`, an internal bridge network. Use it to reach the host's SSH
  gateway at an address such as `192.0.2.10` and to receive webhooks from internal siblings.
  A sibling such as `vault` can use the executor's container service name on `isolate`.
- Optionally attach `ext` when an admin reverse proxy provides dashboard or webhook ingress,
  for example at `https://hooks.example.com`. The host SSH gateway and internal sibling traffic
  use `isolate`.
