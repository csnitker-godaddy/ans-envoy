// A CLI whose entire purpose is printing to a terminal.
#![allow(clippy::print_stdout)]
#![warn(missing_docs)]

//! `ans-probe` — mint ANS-6 artifacts and probe a deployed `ans-envoy`.
//!
//! Two jobs.
//!
//! **Mint.** A caller cannot produce a valid Method-B request without a status
//! token signed by a key the callee trusts, and an identity certificate whose
//! fingerprint that token lists. Standing up a Transparency Log to get those would
//! make a local demo far more work than the thing being demonstrated — so this
//! mints its own TL key and publishes it as a C2SP line for the callee's
//! `static_root_keys`. §4.5 calls that pinned, static posture valid.
//!
//! **Probe.** Then it runs the refusal matrix: replay, duplicate headers, a proof
//! minted for another origin, a body altered in flight. A deployment that answers
//! 200 to a valid request proves very little; one that refuses each of those for
//! the right documented reason is working.
//!
//! Development tool. `publish = false`, and it holds private keys in files — it has
//! no business anywhere near production.

mod bundle;
mod scenarios;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Defaults matching the shipped demo manifests.
const DEFAULT_ANS_NAME: &str = "ans://v1.0.0.caller.example.com";
const DEFAULT_AGENT_ID: &str = "7a4b2e91-83f6-4c12-9d58-bf1e6a3c9d07";
const DEFAULT_TL_SEED: u8 = 0x11;

#[derive(Parser, Debug)]
#[command(
    name = "ans-probe",
    about = "Mint ANS-6 artifacts and probe a deployed ans-envoy (development tool)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Mint a demo bundle: TL key line, status token, receipt, caller identity.
    Mint {
        /// Directory to write the bundle to.
        #[arg(short, long, default_value = "./demo-bundle")]
        out: PathBuf,
        /// Directory holding the committed demo certificates.
        #[arg(long, default_value = "./testdata/demo-agents")]
        agents: PathBuf,
        /// Which demo identity to use.
        #[arg(long, default_value = "caller")]
        agent: String,
        /// The caller's `ans://` name.
        #[arg(long, default_value = DEFAULT_ANS_NAME)]
        ans_name: String,
        /// The caller's agent id.
        #[arg(long, default_value = DEFAULT_AGENT_ID)]
        agent_id: String,
        /// Status-token lifetime in seconds.
        #[arg(long, default_value_t = 3600)]
        ttl: i64,
    },
    /// Run the refusal matrix against a deployed endpoint.
    Scenarios {
        /// Where to send the requests, e.g. `http://127.0.0.1:18443`.
        #[arg(short, long)]
        url: String,
        /// The externally-visible origin the caller signs into `htu`.
        ///
        /// Defaults to `url`. Set this when the address you reach the proxy on is
        /// not the authority it answers as — a port-forward, a cluster IP, a
        /// `NodePort`. It must match the `ans_trusted_authority` the Envoy route
        /// asserts, because §7.7 compares against that and never against the
        /// socket the request arrived on.
        #[arg(long)]
        signed_origin: Option<String>,
        /// Path to request.
        #[arg(long, default_value = "/api/task")]
        path: String,
        /// Bundle directory from `mint`.
        #[arg(short, long, default_value = "./demo-bundle")]
        bundle: PathBuf,
        /// The caller's `ans://` name, matching the minted bundle.
        #[arg(long, default_value = DEFAULT_ANS_NAME)]
        ans_name: String,
        /// The caller's agent id, matching the minted bundle.
        #[arg(long, default_value = DEFAULT_AGENT_ID)]
        agent_id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        println!("error: could not start an async runtime");
        return ExitCode::FAILURE;
    };

    match cli.command {
        Command::Mint {
            out,
            agents,
            agent,
            ans_name,
            agent_id,
            ttl,
        } => mint(&out, &agents, &agent, &ans_name, &agent_id, ttl),
        Command::Scenarios {
            url,
            signed_origin,
            path,
            bundle,
            ans_name,
            agent_id,
        } => {
            let signed = signed_origin.unwrap_or_else(|| url.clone());
            runtime.block_on(probe(&url, &signed, &path, &bundle, &ans_name, &agent_id))
        }
    }
}

fn mint(
    out: &Path,
    agents: &Path,
    agent: &str,
    ans_name: &str,
    agent_id: &str,
    ttl: i64,
) -> ExitCode {
    let minted = match bundle::mint(agents, agent, ans_name, agent_id, DEFAULT_TL_SEED, ttl) {
        Ok(b) => b,
        Err(e) => {
            println!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let written = match bundle::write(&minted, out) {
        Ok(w) => w,
        Err(e) => {
            println!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("Minted a demo bundle for {}\n", minted.ans_name);
    for path in written {
        println!("  {}", path.display());
    }
    println!(
        "\nStatus token expires at {} (in {}s). Re-run `mint` after that; the TL key\n\
         is seed-derived, so the C2SP line below does not change and your deployment\n\
         config stays valid.\n",
        minted.expires_at, ttl
    );
    println!("Put this in ans-authz's `transparency_log.static_root_keys`:\n");
    println!("  static_root_keys = [\"{}\"]\n", minted.c2sp_line);
    println!("Then:  ans-probe scenarios --url http://<host>:<port>");
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_arguments)]
async fn probe(
    url: &str,
    signed_origin: &str,
    path: &str,
    dir: &Path,
    ans_name: &str,
    agent_id: &str,
) -> ExitCode {
    let loaded = match bundle::load(dir, ans_name, agent_id) {
        Ok(b) => b,
        Err(e) => {
            println!("error: {e}\n\nRun `ans-probe mint` first.");
            return ExitCode::FAILURE;
        }
    };

    println!("Probing {url}{path} as {ans_name}");
    if signed_origin != url {
        println!("  signing htu against {signed_origin}{path}");
    }
    println!();
    let outcomes = scenarios::run(url, signed_origin, path, &loaded).await;

    let width = outcomes.iter().map(|o| o.name.len()).max().unwrap_or(20);
    for outcome in &outcomes {
        println!(
            "  {}  {:<width$}  {:<11}  expected {:<26} got {}",
            if outcome.passed { "PASS" } else { "FAIL" },
            outcome.name,
            outcome.spec,
            outcome.expected,
            outcome.actual,
            width = width
        );
    }

    let failed = outcomes.iter().filter(|o| !o.passed).count();
    println!();
    if failed == 0 {
        println!("All {} checks passed.", outcomes.len());
        return ExitCode::SUCCESS;
    }

    println!("{failed} of {} checks failed.\n", outcomes.len());
    println!("Common causes:");
    println!(
        "  DUPLICATE_HEADER not returned   → `encode_raw_headers: true` is missing on the\n\
         \x20                                 Envoy ext_authz filter (§4.6)."
    );
    println!(
        "  the other-origin proof allowed  → the htu comparison URL is coming from the\n\
         \x20                                 request rather than context_extensions (§7.7)."
    );
    println!(
        "  CONTENT_BINDING_MISMATCH on a   → `with_request_body` is missing, so bodies never\n\
         \x20 valid bound body               reach ans-authz (§7.13)."
    );
    println!(
        "  everything 503                  → ans-authz is unreachable from Envoy; check the\n\
         \x20                                 cluster address and that it started (it refuses\n\
         \x20                                 to start on a non-conformant config)."
    );
    ExitCode::FAILURE
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
    fn scenarios_requires_a_url() {
        assert!(Cli::try_parse_from(["ans-probe", "scenarios"]).is_err());
        assert!(
            Cli::try_parse_from(["ans-probe", "scenarios", "--url", "http://localhost:8080"])
                .is_ok()
        );
        // The signed origin is optional and defaults to the send address.
        assert!(
            Cli::try_parse_from([
                "ans-probe",
                "scenarios",
                "--url",
                "http://127.0.0.1:18443",
                "--signed-origin",
                "https://api.example.com",
            ])
            .is_ok()
        );
    }

    #[test]
    fn mint_writes_a_usable_bundle() {
        let dir = std::env::temp_dir().join(format!("ans-probe-test-{}", std::process::id()));
        let agents = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("testdata")
            .join("demo-agents");

        let minted = bundle::mint(
            &agents,
            "caller",
            DEFAULT_ANS_NAME,
            DEFAULT_AGENT_ID,
            DEFAULT_TL_SEED,
            3600,
        )
        .expect("mint should succeed");

        // The C2SP line is what the callee trusts, so the check that matters is
        // that the SDK's own parser accepts it — a round trip, not a shape guess.
        //
        // Note you cannot count fields with `split('+')`: standard base64 contains
        // `+`, which is also the signed-note field separator, so the key material
        // itself splits. §4.5's format is parsed from the left with a limit.
        assert!(minted.c2sp_line.starts_with("tl.demo.invalid+"));
        ans_verify::ScittKeyStore::from_c2sp_keys(std::slice::from_ref(&minted.c2sp_line))
            .expect("the minted C2SP line must parse as a trusted key");
        assert_ne!(minted.status_token_b64, "");
        assert_ne!(minted.receipt_b64, "");

        // And the identity must actually be able to sign a proof.
        let signer = minted.signer().expect("signer should build");
        let proof = signer
            .sign("POST", "https://api.example.com/api/task", None)
            .expect("proof should mint");
        assert_eq!(
            proof.split('.').count(),
            3,
            "compact JWS has three segments"
        );

        bundle::write(&minted, &dir).expect("write should succeed");
        let loaded =
            bundle::load(&dir, DEFAULT_ANS_NAME, DEFAULT_AGENT_ID).expect("load should succeed");
        assert_eq!(loaded.c2sp_line, minted.c2sp_line);
        assert_eq!(loaded.status_token_b64, minted.status_token_b64);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_tl_key_is_seed_derived_so_the_config_line_is_stable() {
        // Otherwise every `mint` would invalidate the deployment's ConfigMap.
        let agents = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("testdata")
            .join("demo-agents");
        let one = bundle::mint(
            &agents,
            "caller",
            DEFAULT_ANS_NAME,
            DEFAULT_AGENT_ID,
            0x11,
            60,
        )
        .unwrap();
        let two = bundle::mint(
            &agents,
            "caller",
            DEFAULT_ANS_NAME,
            DEFAULT_AGENT_ID,
            0x11,
            60,
        )
        .unwrap();
        assert_eq!(one.c2sp_line, two.c2sp_line);

        let other = bundle::mint(
            &agents,
            "caller",
            DEFAULT_ANS_NAME,
            DEFAULT_AGENT_ID,
            0x22,
            60,
        )
        .unwrap();
        assert_ne!(one.c2sp_line, other.c2sp_line);
    }
}
