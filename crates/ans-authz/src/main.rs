//! `ans-authz` — an Envoy `ext_authz` authorization server implementing ANS-6
//! agent-to-agent authentication.
//!
//! Three subcommands, and two of them exist because ANS-6 makes conformance a
//! property of things outside this binary:
//!
//! - `serve` — run the authorizer.
//! - `validate-config` — check a config without starting. §7.7 requires failing
//!   startup on a non-conformant configuration, and this is that check, runnable
//!   in CI.
//! - `validate-envoy` — lint the Envoy half. Five Envoy settings decide whether a
//!   deployment satisfies ANS-6 and none of them live here.

mod admin;
mod runtime;
mod service;
mod telemetry;

use std::net::SocketAddr;
use std::process::ExitCode;

use ans_envoy_adapter::AuthorityResolver;
use ans_envoy_config::{Config, MethodsConfig, Severity};
use clap::{Parser, Subcommand};
use envoy_types::pb::envoy::service::auth::v3::authorization_server::AuthorizationServer;

use crate::admin::{AdminState, Observed};
use crate::service::AnsAuthz;
use crate::telemetry::Telemetry;

#[derive(Parser, Debug)]
#[command(
    name = "ans-authz",
    about = "Envoy ext_authz server for ANS-6 agent-to-agent authentication",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the authorization server.
    Serve {
        /// Path to the TOML configuration file.
        #[arg(short, long)]
        config: String,
    },
    /// Validate a configuration file and exit.
    ValidateConfig {
        /// Path to the TOML configuration file.
        #[arg(short, long)]
        config: String,
    },
    /// Lint an Envoy configuration for the settings ANS-6 depends on.
    ValidateEnvoy {
        /// Path to the Envoy YAML (bootstrap, fragment, or xDS dump).
        path: String,
        /// Apply the additional checks Method A requires.
        #[arg(long)]
        method_a: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve { config } => run_serve(&config),
        Command::ValidateConfig { config } => validate_config(&config),
        Command::ValidateEnvoy { path, method_a } => validate_envoy(&path, method_a),
    }
}

/// Initialise logging. JSON when `ANS_AUTHZ_LOG_JSON` is set, otherwise human.
fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter =
        EnvFilter::try_from_env("ANS_AUTHZ_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("ANS_AUTHZ_LOG_JSON").is_ok() {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn run_serve(path: &str) -> ExitCode {
    init_tracing();

    let config = match ans_envoy_config::load(path) {
        Ok(c) => c,
        Err(e) => {
            // §7.7: "Implementations MUST fail startup when neither is
            // configured." This is that failure, and it is deliberately loud.
            tracing::error!(error = %e, "refusing to start");
            return ExitCode::FAILURE;
        }
    };

    for warning in ans_envoy_config::warnings(&config) {
        tracing::warn!(field = %warning.field, spec = warning.spec, "{}", warning.message);
    }
    log_effective_policy(&config);

    let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    else {
        tracing::error!("could not start the async runtime");
        return ExitCode::FAILURE;
    };

    rt.block_on(async move {
        match serve(config).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                tracing::error!(error = %e, "server stopped");
                ExitCode::FAILURE
            }
        }
    })
}

/// §11.1 requires a deployment to document the values it runs. Logging them at
/// startup means the record exists wherever the logs go, rather than only in
/// whatever file happened to be deployed.
fn log_effective_policy(config: &Config) {
    tracing::info!(
        methods = ?config.verification.methods,
        require_receipt = config.verification.require_receipt,
        pop_skew_secs = config.verification.pop_skew_secs,
        status_skew_secs = config.verification.status_skew_secs,
        content_binding = ?config.verification.content_binding,
        authority_mode = ?config.authority.mode,
        replay_backend = ?config.replay.backend,
        replicas = config.replay.replicas,
        peer_pinning = config.verification.allowed_ans_names.len(),
        "effective ANS-6 policy"
    );
}

async fn serve(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rt = runtime::build(&config).await?;

    let telemetry = Telemetry::new();
    let observed = Observed::new();
    let resolver = AuthorityResolver::from_config(&config.authority);

    let admin_state = AdminState {
        telemetry: telemetry.clone(),
        replay: rt.replay_metrics.clone(),
        replay_backend: rt.replay_backend,
        replay_shared: rt.replay_shared,
        observed: observed.clone(),
    };

    let admin_addr: SocketAddr = config.server.admin_listen.parse()?;
    let admin = tokio::spawn(async move {
        if let Err(e) = admin::serve(admin_addr, admin_state, shutdown_signal()).await {
            tracing::error!(error = %e, "admin surface failed");
        }
    });

    let authz = AnsAuthz::new(rt.verifier.clone(), resolver, telemetry, observed);
    let server = tonic::transport::Server::builder().add_service(AuthorizationServer::new(authz));

    if let Some(uds) = config.server.uds_path.as_deref() {
        // A stale socket from a previous run would make bind fail. Removing it is
        // safe: two processes bound to one path is not a state we support.
        let _ = std::fs::remove_file(uds);
        let listener = tokio::net::UnixListener::bind(uds)?;
        tracing::info!(path = uds, "ext_authz listening on unix socket");
        server
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::UnixListenerStream::new(listener),
                shutdown_signal(),
            )
            .await?;
    } else {
        let addr: SocketAddr = config
            .server
            .listen
            .as_deref()
            .unwrap_or("127.0.0.1:10003")
            .parse()?;
        tracing::info!(%addr, "ext_authz listening");
        server.serve_with_shutdown(addr, shutdown_signal()).await?;
    }

    admin.abort();
    Ok(())
}

/// Resolve on SIGINT or SIGTERM.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}

/// `validate-config` — CI-runnable form of the §7.7 startup check.
#[allow(clippy::print_stdout)]
fn validate_config(path: &str) -> ExitCode {
    match ans_envoy_config::load(path) {
        Ok(config) => {
            println!("{path}: conformant");
            for warning in ans_envoy_config::warnings(&config) {
                println!("  warning: {warning}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{path}: NOT conformant\n{e}");
            ExitCode::FAILURE
        }
    }
}

/// `validate-envoy` — lint the half of the deliverable that lives in Envoy.
#[allow(clippy::print_stdout)]
fn validate_envoy(path: &str, method_a: bool) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            println!("{path}: cannot read: {e}");
            return ExitCode::FAILURE;
        }
    };

    let findings = match ans_envoy_config::envoy_lint::lint(&text, method_a) {
        Ok(f) => f,
        Err(e) => {
            // An unparseable config must not be reported as "no findings": that
            // would claim success on a file the linter never read.
            println!("{path}: cannot lint: {e}");
            return ExitCode::FAILURE;
        }
    };

    let errors = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .count();

    if findings.is_empty() {
        println!("{path}: no findings");
        return ExitCode::SUCCESS;
    }

    println!("{path}:");
    for finding in &findings {
        println!("  {finding}");
    }

    if errors > 0 {
        println!("\n{errors} error(s): this configuration is not ANS-6 conformant.");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Whether a configuration wants Method A, for the linter's stricter checks.
#[allow(dead_code)]
fn wants_method_a(config: &Config) -> bool {
    matches!(
        config.verification.methods,
        MethodsConfig::MethodA | MethodsConfig::Both
    )
}

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn serve_requires_a_config_path() {
        assert!(Cli::try_parse_from(["ans-authz", "serve"]).is_err());
        assert!(Cli::try_parse_from(["ans-authz", "serve", "--config", "a.toml"]).is_ok());
    }

    #[test]
    fn validate_envoy_takes_a_path_and_an_optional_method_a_flag() {
        let cli = Cli::try_parse_from(["ans-authz", "validate-envoy", "envoy.yaml"]).unwrap();
        match cli.command {
            Command::ValidateEnvoy { path, method_a } => {
                assert_eq!(path, "envoy.yaml");
                assert!(!method_a);
            }
            other => panic!("unexpected: {other:?}"),
        }

        let cli = Cli::try_parse_from(["ans-authz", "validate-envoy", "envoy.yaml", "--method-a"])
            .unwrap();
        match cli.command {
            Command::ValidateEnvoy { method_a, .. } => assert!(method_a),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn validating_a_missing_config_fails() {
        assert_eq!(
            validate_config("/nonexistent/ans-authz.toml"),
            ExitCode::FAILURE
        );
    }

    #[test]
    fn validating_a_missing_envoy_file_fails() {
        assert_eq!(
            validate_envoy("/nonexistent/envoy.yaml", false),
            ExitCode::FAILURE
        );
    }
}
