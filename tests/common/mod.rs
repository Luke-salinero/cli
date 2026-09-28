//! Helpers shared by the hand-written integration tests for `onboard`. Not a
//! test crate itself: `tests/common/` is the Cargo idiom for code that
//! `tests/*.rs` pull in with `mod common;`.
//!
//! Every CLI here runs with the developer's own environment kept out: `HOME`
//! at a temp dir and the file credential store (so a real keychain and
//! `~/.elevenlabs/config.json` play no part), no key, base URL, partner token
//! or output preference from the shell, and git's global and system config
//! ignored (a global gitignore that lists `.env.local` would otherwise change
//! what the CLI sees).

#![allow(dead_code)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// The CLI pointed at `server`, run in `cwd`, with `home` as `HOME`.
pub fn cli(home: &Path, cwd: &Path, server: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_elevenlabs"));
    cmd.args(["--base-url", server])
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("NO_COLOR", "1")
        .env("FERN_CLI_CREDENTIAL_STORE", "file")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("ELEVENLABS_API_KEY")
        .env_remove("ELEVENLABS_BASE_URL")
        .env_remove("ELEVENLABS_VIA")
        .env_remove("ELEVENLABS_OUTPUT");
    cmd
}

/// Store a sign-in the way `auth login` would, via the framework's own paste path.
pub fn seed_sign_in(home: &Path, cwd: &Path, server: &str, token: &str) {
    let mut child = cli(
        home,
        cwd,
        server,
        &["auth", "login", "--with-token", "--scheme", "OAuth"],
    )
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .expect("spawn auth login");
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(token.as_bytes())
        .expect("write the token to auth login");
    assert!(
        child.wait().expect("auth login exits").success(),
        "seeding the sign-in failed"
    );
}

/// Errors go to stdout as JSON when piped, so failures are looked for in both streams.
pub fn all_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Parse stdout as JSON, failing with both streams when the CLI did not succeed.
pub fn json_stdout(output: &Output) -> serde_json::Value {
    assert!(output.status.success(), "{}", all_output(output));
    serde_json::from_slice(&output.stdout).expect("stdout is JSON")
}

/// `git init` plus one commit tracking `tracked`, so `ls-files` has something to find.
pub fn git_repo_tracking(dir: &Path, tracked: &str) {
    let git = |args: &[&str]| {
        let out = Command::new("git")
            .args(args)
            .current_dir(dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .output()
            .expect("git runs");
        assert!(
            out.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    git(&["init", "-q"]);
    std::fs::write(dir.join(tracked), "TRACKED=1\n").unwrap();
    git(&["add", tracked]);
    git(&["-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"]);
}
