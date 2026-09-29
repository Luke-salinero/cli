//! Integration tests for `elevenlabs onboard` and `onboard status`, against
//! a local mock API.
//!
//! The browser sign-in itself is the framework's and is not driven here;
//! these cover everything around it: what `status` reports for each place a
//! key can live, the refusals that must happen before a browser opens, and
//! the `.env.local` loading every command relies on.

mod common;

use std::path::Path;

use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use common::{all_output, cli, git_repo_tracking, json_stdout, seed_sign_in};

const KEY: &str = "sk_0123456789abcdef0123456789abcdef01234567";

fn temp() -> (tempfile::TempDir, tempfile::TempDir) {
    (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
}

async fn user_endpoint_accepting(server: &MockServer, key: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/user"))
        .and(header("xi-api-key", key))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"user_id": "user_1"})))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/user"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "detail": {"status": "invalid_api_key", "message": "Invalid API key"}
        })))
        .mount(server)
        .await;
}

// ── status ──────────────────────────────────────────────────────────

#[tokio::test]
async fn status_with_nothing_configured_reports_that_and_exits_zero() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status"],
    )
    .output()
    .unwrap();

    let facts = json_stdout(&out);
    assert_eq!(facts["signed_in"], false);
    assert!(
        facts["browser_reachable"].is_boolean(),
        "the skill branches on this before opening anything"
    );
    assert_eq!(facts["env_file"], ".env.local");
    assert_eq!(facts["env_file_exists"], false);
    assert_eq!(facts["api_key_present"], false);
    assert_eq!(facts["api_key_source"], "none");
    assert!(facts["api_key_valid"].is_null());
    assert!(facts["api_key_last4"].is_null());
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        0,
        "nothing to ask the API about"
    );
}

#[tokio::test]
async fn status_validates_the_key_in_the_env_file_without_printing_it() {
    let server = MockServer::start().await;
    user_endpoint_accepting(&server, KEY).await;
    let (home, cwd) = temp();
    std::fs::write(
        cwd.path().join(".env.local"),
        format!("ELEVENLABS_API_KEY={KEY}\n"),
    )
    .unwrap();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status"],
    )
    .output()
    .unwrap();

    let facts = json_stdout(&out);
    assert_eq!(facts["env_file_exists"], true);
    assert_eq!(facts["api_key_present"], true);
    assert_eq!(facts["api_key_source"], "env_file");
    assert_eq!(facts["api_key_valid"], true);
    assert_eq!(facts["api_key_last4"], "4567");
    assert!(
        !all_output(&out).contains(KEY),
        "the key never appears in the output"
    );
}

#[tokio::test]
async fn status_reports_a_key_the_api_rejects() {
    let server = MockServer::start().await;
    user_endpoint_accepting(&server, "sk_some_other_key").await;
    let (home, cwd) = temp();
    std::fs::write(
        cwd.path().join(".env"),
        format!("ELEVENLABS_API_KEY={KEY}\n"),
    )
    .unwrap();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status", "--env-file", ".env"],
    )
    .output()
    .unwrap();

    let facts = json_stdout(&out);
    assert_eq!(facts["env_file"], ".env");
    assert_eq!(facts["api_key_source"], "env_file");
    assert_eq!(facts["api_key_valid"], false);
}

#[tokio::test]
async fn status_prefers_a_key_from_the_environment_and_says_so() {
    let server = MockServer::start().await;
    user_endpoint_accepting(&server, KEY).await;
    let (home, cwd) = temp();
    std::fs::write(
        cwd.path().join(".env.local"),
        "ELEVENLABS_API_KEY=sk_file_key_0000000000000000\n",
    )
    .unwrap();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status"],
    )
    .env("ELEVENLABS_API_KEY", KEY)
    .output()
    .unwrap();

    let facts = json_stdout(&out);
    assert_eq!(facts["api_key_source"], "env");
    assert_eq!(facts["api_key_valid"], true);
    assert_eq!(facts["api_key_last4"], "4567");
}

#[tokio::test]
async fn status_sees_a_stored_sign_in() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();
    seed_sign_in(home.path(), cwd.path(), &server.uri(), "a-bearer-token");

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status"],
    )
    .output()
    .unwrap();

    assert_eq!(json_stdout(&out)["signed_in"], true);
}

#[tokio::test]
async fn status_prints_prose_when_asked_for_a_table() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status", "--format", "table"],
    )
    .output()
    .unwrap();

    assert!(out.status.success(), "{}", all_output(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Signed in:"), "{text}");
    assert!(text.contains("API key:"), "{text}");
    assert!(serde_json::from_str::<serde_json::Value>(&text).is_err());
}

// ── `.env.local` is loaded for every command ────────────────────────

#[tokio::test]
async fn a_key_in_env_local_is_used_by_other_commands() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/user"))
        .and(header("xi-api-key", KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "user_id": "user_1",
            "subscription": {"tier": "free", "character_count": 0, "character_limit": 10000, "status": "free"},
            "is_new_user": false,
            "created_at": 0
        })))
        .mount(&server)
        .await;
    let (home, cwd) = temp();
    std::fs::write(
        cwd.path().join(".env.local"),
        format!("ELEVENLABS_API_KEY={KEY}\n"),
    )
    .unwrap();

    let out = cli(home.path(), cwd.path(), &server.uri(), &["user", "get"])
        .output()
        .unwrap();

    assert!(out.status.success(), "{}", all_output(&out));
    let requests = server.received_requests().await.unwrap();
    assert!(requests
        .iter()
        .any(|r| r.headers.get("xi-api-key").is_some_and(|v| v == KEY)));
}

#[tokio::test]
async fn env_local_never_overrides_a_key_already_in_the_environment() {
    let server = MockServer::start().await;
    user_endpoint_accepting(&server, KEY).await;
    let (home, cwd) = temp();
    std::fs::write(
        cwd.path().join(".env.local"),
        "ELEVENLABS_API_KEY=sk_file_key_0000000000000000\n",
    )
    .unwrap();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status"],
    )
    .env("ELEVENLABS_API_KEY", KEY)
    .output()
    .unwrap();

    assert_eq!(json_stdout(&out)["api_key_source"], "env");
}

#[tokio::test]
async fn env_local_wins_over_env_for_the_key() {
    let server = MockServer::start().await;
    user_endpoint_accepting(&server, KEY).await;
    let (home, cwd) = temp();
    std::fs::write(
        cwd.path().join(".env"),
        "ELEVENLABS_API_KEY=sk_stale_key_00000000000000000\n",
    )
    .unwrap();
    std::fs::write(
        cwd.path().join(".env.local"),
        format!("ELEVENLABS_API_KEY={KEY}\n"),
    )
    .unwrap();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status"],
    )
    .output()
    .unwrap();

    let facts = json_stdout(&out);
    assert_eq!(facts["api_key_source"], "env_file");
    assert_eq!(facts["api_key_last4"], "4567");
    assert_eq!(facts["api_key_valid"], true);
}

// ── refusals before any browser opens ───────────────────────────────

#[tokio::test]
async fn a_remote_session_is_sent_to_the_api_keys_page_instead() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "--product", "text-to-speech"],
    )
    .env("SSH_CONNECTION", "10.0.0.2 51000 10.0.0.1 22")
    .output()
    .unwrap();

    assert!(!out.status.success());
    // Piped, the refusal is the JSON error on stdout, like every other error.
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("No browser can reach this machine"), "{text}");
    assert!(text.contains("api-keys"), "{text}");
    assert!(text.contains("--no-browser"), "{text}");
    assert!(!cwd.path().join(".env.local").exists(), "nothing written");
    assert_eq!(server.received_requests().await.unwrap().len(), 0);

    let status = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "status"],
    )
    .env("SSH_CONNECTION", "10.0.0.2 51000 10.0.0.1 22")
    .output()
    .unwrap();
    assert_eq!(json_stdout(&status)["browser_reachable"], false);
}

#[tokio::test]
async fn an_unknown_product_is_refused() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "--product", "tts", "--no-browser"],
    )
    .output()
    .unwrap();

    assert!(!out.status.success());
    let text = all_output(&out);
    assert!(
        text.contains("text-to-speech"),
        "the valid slugs are listed: {text}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn an_env_file_git_tracks_is_refused() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();
    git_repo_tracking(cwd.path(), ".env");

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "--env-file", ".env", "--no-browser"],
    )
    .output()
    .unwrap();

    assert!(!out.status.success());
    let text = all_output(&out);
    assert!(text.contains("tracked by git"), "{text}");
    assert_eq!(
        std::fs::read_to_string(cwd.path().join(".env")).unwrap(),
        "TRACKED=1\n"
    );
}

#[tokio::test]
async fn an_existing_key_is_kept_unless_replace_is_passed() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();
    std::fs::write(
        cwd.path().join(".env.local"),
        format!("ELEVENLABS_API_KEY={KEY}\n"),
    )
    .unwrap();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "--no-browser"],
    )
    .output()
    .unwrap();

    assert!(!out.status.success());
    let text = all_output(&out);
    assert!(text.contains("already sets ELEVENLABS_API_KEY"), "{text}");
    assert!(
        text.contains("4567"),
        "the key is named by its last four characters only: {text}"
    );
    assert!(!text.contains(KEY));
    assert!(text.contains("--replace"));
}

#[tokio::test]
async fn a_placeholder_line_does_not_count_as_an_existing_key() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();
    std::fs::write(cwd.path().join(".env.local"), "ELEVENLABS_API_KEY=\n").unwrap();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "--product", "music", "--dry-run"],
    )
    .output()
    .unwrap();

    assert!(out.status.success(), "{}", all_output(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("[DRY RUN]"));
}

#[tokio::test]
async fn a_symlinked_env_file_is_refused() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();
    let target = cwd.path().join("elsewhere.env");
    std::fs::write(&target, "").unwrap();
    symlink(&target, &cwd.path().join(".env.local"));

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &["onboard", "--no-browser"],
    )
    .output()
    .unwrap();

    assert!(!out.status.success());
    assert!(all_output(&out).contains("symlink"));
}

#[cfg(unix)]
fn symlink(target: &Path, link: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(windows)]
fn symlink(target: &Path, link: &Path) {
    std::os::windows::fs::symlink_file(target, link).unwrap();
}

#[tokio::test]
async fn dry_run_names_the_approval_page_the_product_and_the_file_and_opens_nothing() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();

    let out = cli(
        home.path(),
        cwd.path(),
        &server.uri(),
        &[
            "onboard",
            "--product",
            "text-to-speech",
            "--env-file",
            "app/.env.local",
            "--dry-run",
        ],
    )
    .output()
    .unwrap();

    assert!(out.status.success(), "{}", all_output(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("https://elevenlabs.io/app/oauth/authorize"),
        "{text}"
    );
    assert!(text.contains("text-to-speech"), "{text}");
    assert!(text.contains("app/.env.local"), "{text}");
    assert!(
        !cwd.path().join("app").exists(),
        "a dry run creates nothing"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn onboard_is_listed_in_the_top_level_help() {
    let server = MockServer::start().await;
    let (home, cwd) = temp();

    let out = cli(home.path(), cwd.path(), &server.uri(), &["--help"])
        .output()
        .unwrap();

    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("onboard"), "{text}");
    assert!(text.contains("API key in this project"), "{text}");
}
