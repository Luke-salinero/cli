//! `onboard`: sign in and put a working API key in the project, in one
//! command. `onboard status` reports what is already in place.
//!
//! The browser does the sensitive work. `onboard` runs the same sign-in as
//! `auth login`, adding the product and hand-off parameters to the approval
//! page's URL. When the developer clicks Authorize, the page creates a key
//! scoped to that product in their web session and copies it to the
//! clipboard. Once the sign-in has completed (the `state` check and token
//! exchange included), this command reads the clipboard, keeps the key only
//! if it belongs to the account that just signed in, writes it to the env
//! file, ignores that file in git, and clears the clipboard. The key is
//! never printed.
//!
//! Why a command of its own rather than flags on `auth login`: that command
//! belongs to the Fern runtime and takes no options from our generator
//! configuration. It is reused wholesale through [`PkceLoginFlow`], so the
//! listener, PKCE, token storage and callback pages are the ones `auth login`
//! has, and the stored sign-in is the one every other command uses.
//!
//! What the page copies is the only channel back: the callback parser keeps
//! nothing but the OAuth parameters. A key means one was created; nothing
//! means the page could not create one and has told the developer why. The
//! page may also leave a short `elevenlabs:<reason>` note instead, which
//! this command recognizes so the reason can be reported exactly.

use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use fern_cli_sdk::app::CliApp;
use fern_cli_sdk::auth::{active_store, LoginContext, LoginFlow, PkceLoginFlow, TokenBundle};
use fern_cli_sdk::error::CliError;
use fern_cli_sdk::formatter::OutputPipeline;
use fern_cli_sdk::openapi::AppContext;
use serde_json::{json, Value};

use super::util::{downcast_ctx, dry_run_flag, opt_string};
use super::{api, settings};

// ── The sign-in, as `main.rs` pins it ────────────────────────────────
//
// `fern generate` rewrites `main.rs`; the constants below repeat it so this
// command can build the same flow, and `tests::main_rs_declares_the_same_sign_in`
// fails the build the moment the two drift apart.

pub(super) const CLI_NAME: &str = "elevenlabs";
const SCHEME: &str = "OAuth";
const CLIENT_ID: &str = "c9c18126-5718-406a-8a12-21b69e5a888d";
const AUTHORIZE_URL: &str = "https://elevenlabs.io/app/oauth/authorize";
const TOKEN_URL: &str = "https://api.us.elevenlabs.io/v1/oauth/token";
const REDIRECT_HOST: &str = "localhost";
const REDIRECT_PORTS: [u16; 3] = [8484, 8483, 8482];
const SUCCESS_URL: &str = "https://elevenlabs.io/app/oauth/cli/success";
const ERROR_URL: &str = "https://elevenlabs.io/app/oauth/cli/error";
const SCOPES: &[&str] = &[
    "text_to_speech",
    "speech_to_speech",
    "speech_to_text",
    "sound_generation",
    "audio_isolation",
    "voice_generation",
    "forced_alignment",
    "music_generation",
    "image_video_generation",
    "flows",
    "models_read",
    "voices_read",
    "voices_write",
    "speech_history_read",
    "speech_history_write",
    "dubbing_read",
    "dubbing_write",
    "pronunciation_dictionaries_read",
    "pronunciation_dictionaries_write",
    "projects_read",
    "projects_write",
    "convai_read",
    "convai_write",
    "add_voice_from_voice_library",
    "create_instant_voice_clone",
    "create_professional_voice_clone",
    "user_read",
    "workspace_read",
];

/// The API host the sign-in is issued by. The account check asks it, not the
/// project's residency host, so the bearer and the key are compared where the
/// bearer is valid.
const OAUTH_API_BASE: &str = "https://api.us.elevenlabs.io";

// ── The contract with the approval page and the skill ────────────────

/// Products the approval page knows how to scope a key to. Named after the
/// skill directories in `elevenlabs/skills`, which is what an agent has in
/// front of it. The page owns the slug-to-permissions table; this list only
/// lets a typo fail here instead of in the browser.
pub(super) const PRODUCTS: &[&str] = &[
    "text-to-speech",
    "speech-to-text",
    "voice-changer",
    "sound-effects",
    "music",
    "voice-isolator",
    "dubbing",
    "agents",
    "speech-engine",
];

/// The env var every SDK and this CLI read the key from.
pub(super) const API_KEY_ENV: &str = "ELEVENLABS_API_KEY";
/// Where the key goes when the skill does not say. Framework tooling loads
/// it, fewer agent harnesses read it into context than `.env`.
const DEFAULT_ENV_FILE: &str = ".env.local";
const API_KEYS_PAGE_URL: &str = "https://elevenlabs.io/app/settings/api-keys";
/// What the page may copy instead of a key when it could not create one.
const SENTINEL_PREFIX: &str = "elevenlabs:";
/// `key_reason` when the API could not be reached to check whose key it is.
const COULD_NOT_VERIFY: &str = "could_not_verify";
const GITIGNORE_NOTE: &str = "# Local secrets written by `elevenlabs onboard`\n";
const PLACEHOLDER_NOTE: &str =
    "# Paste your ElevenLabs API key below. Click \"Copy key\" on the approval page, or \
     create one at https://elevenlabs.io/app/settings/api-keys. Never paste it into a chat.";
/// For an account that cannot create keys this way there is no Copy key
/// button to point at, so the note names what will work instead.
const LEGACY_PLACEHOLDER_NOTE: &str = "# Paste your ElevenLabs API key below. Create one at \
     https://elevenlabs.io/app/settings/api-keys, or ask a workspace administrator for one. \
     Never paste it into a chat.";

/// What the run ended with, in the words the skill branches on.
#[derive(Clone, PartialEq, Eq, Debug)]
enum KeyStatus {
    /// A key from the page, validated against the sign-in, in the env file.
    Created,
    /// The page copied nothing (or the user continued without copying).
    NoKey,
    /// The clipboard held a key that is not this account's.
    ClipboardInvalid,
    /// The page's note: the flow is off for this account.
    NotAvailable,
    /// The page's note: this role cannot create keys.
    NotPermitted,
    /// The page's note (key creation failed, with its reason), or this
    /// command's own [`COULD_NOT_VERIFY`].
    Failed(String),
}

impl KeyStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::NoKey => "no_key",
            Self::ClipboardInvalid => "clipboard_invalid",
            Self::NotAvailable => "not_available",
            Self::NotPermitted => "not_permitted",
            Self::Failed(_) => "failed",
        }
    }

    /// What the skill should do now.
    fn next(&self) -> &'static str {
        match self {
            Self::Created => "none",
            Self::NoKey | Self::ClipboardInvalid | Self::Failed(_) => "paste_key",
            Self::NotAvailable | Self::NotPermitted => "legacy",
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            Self::Failed(reason) => Some(reason),
            _ => None,
        }
    }
}

/// What the clipboard held after the sign-in.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Clip {
    Key(String),
    Note(KeyStatus),
    Nothing,
}

/// A key as the API mints them: `sk_` and hex, with an optional residency
/// suffix. Anything else on the clipboard is not ours to touch.
fn looks_like_key(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("sk_") else {
        return false;
    };
    let hex_len = rest.bytes().take_while(u8::is_ascii_hexdigit).count();
    if hex_len < 16 {
        return false;
    }
    match &rest[hex_len..] {
        "" => true,
        suffix => suffix.strip_prefix("_residency_").is_some_and(|tag| {
            !tag.is_empty()
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        }),
    }
}

fn classify(text: Option<&str>) -> Clip {
    let Some(text) = text.map(str::trim).filter(|t| !t.is_empty()) else {
        return Clip::Nothing;
    };
    if looks_like_key(text) {
        return Clip::Key(text.to_string());
    }
    let Some(note) = text.strip_prefix(SENTINEL_PREFIX) else {
        return Clip::Nothing;
    };
    // The note is printed back to the user, so only a short machine code is
    // accepted: no newlines, no escape sequences, nothing that could dress up
    // as this command's own output.
    let is_code = !note.is_empty()
        && note.len() <= 64
        && note
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'));
    if !is_code {
        return Clip::Nothing;
    }
    Clip::Note(match note {
        "not_available" => KeyStatus::NotAvailable,
        "not_permitted" => KeyStatus::NotPermitted,
        other => KeyStatus::Failed(
            other
                .strip_prefix("failed:")
                .filter(|code| !code.is_empty())
                .unwrap_or(other)
                .to_string(),
        ),
    })
}

// ── The clipboard ────────────────────────────────────────────────────

/// Read once, clear once. A trait so the hand-off can be tested without a
/// display server.
trait Clipboard {
    fn read(&mut self) -> Option<String>;
    fn clear(&mut self);
}

struct SystemClipboard(Option<arboard::Clipboard>);

impl SystemClipboard {
    /// `None` inside when there is no clipboard to speak of: a headless
    /// Linux session, a container, an SSH login.
    fn open() -> Self {
        Self(arboard::Clipboard::new().ok())
    }
}

impl Clipboard for SystemClipboard {
    fn read(&mut self) -> Option<String> {
        self.0.as_mut()?.get_text().ok()
    }

    fn clear(&mut self) {
        if let Some(clipboard) = self.0.as_mut() {
            let _ = clipboard.clear();
        }
    }
}

// ── The env file ─────────────────────────────────────────────────────

fn key_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    trimmed
        .strip_prefix(API_KEY_ENV)
        .is_some_and(|rest| rest.trim_start().starts_with('='))
}

/// The value on the key line, if there is one: `KEY=value`, `export KEY=value`,
/// quotes stripped. Empty when the line is a placeholder.
fn key_value(line: &str) -> Option<String> {
    if !key_line(line) {
        return None;
    }
    let (_, value) = line.split_once('=')?;
    let value = value.split(" #").next().unwrap_or(value).trim();
    Some(value.trim_matches(|c| c == '"' || c == '\'').to_string())
}

fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// The key the file sets, if any. `Some("")` is a placeholder line.
fn file_key(contents: &str) -> Option<String> {
    strip_bom(contents).lines().find_map(key_value)
}

/// Replace the existing `ELEVENLABS_API_KEY=` line or append one, keeping
/// everything else byte for byte: line endings, a byte-order mark, the
/// presence or absence of a final newline.
fn with_key(contents: &str, key: &str) -> String {
    let newline = if contents.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let assignment = format!("{API_KEY_ENV}={key}");
    let mut out = String::with_capacity(contents.len() + assignment.len() + newline.len());
    let mut replaced = false;
    for (index, line) in contents.split_inclusive('\n').enumerate() {
        let body = line.trim_end_matches(['\r', '\n']);
        let ending = &line[body.len()..];
        let (bom, body) = if index == 0 {
            let stripped = strip_bom(body);
            (&body[..body.len() - stripped.len()], stripped)
        } else {
            ("", body)
        };
        if !replaced && key_line(body) {
            replaced = true;
            out.push_str(bom);
            out.push_str(&assignment);
            out.push_str(ending);
        } else {
            out.push_str(line);
        }
    }
    if !replaced {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push_str(newline);
        }
        out.push_str(&assignment);
        out.push_str(newline);
    }
    out
}

/// The placeholder for a key that has to be pasted by hand: an empty
/// assignment under a note saying where the key comes from. Idempotent, so a
/// second failed run does not stack notes.
fn with_placeholder(contents: &str, note: &str) -> String {
    if file_key(contents).is_some() {
        return contents.to_string();
    }
    let newline = if contents.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut out = contents.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(newline);
    }
    out.push_str(note);
    out.push_str(newline);
    out.push_str(API_KEY_ENV);
    out.push('=');
    out.push_str(newline);
    out
}

/// The env file's contents, or `None` when there is no file yet.
fn read_env_file(path: &Path, display: &str) -> Result<Option<String>, CliError> {
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(Some(contents)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(CliError::Validation(format!(
            "Could not read {display}: {e}. Fix or move it, or pass --env-file to use another file."
        ))),
    }
}

/// The env file, opened before the browser opens with the rules the write
/// follows: no symlinks, owner-only permissions on a new file. A permission
/// problem or a full disk shows up before a key exists that would then have
/// nowhere to go, and the key is written through this same handle, so nothing
/// swapped in at the path in between can receive it. A file this creates is
/// removed again on drop unless something was written.
struct Probe {
    file: std::fs::File,
    path: PathBuf,
    created: bool,
    written: bool,
}

impl Probe {
    fn open(path: &Path, display: &str, exists: bool) -> Result<Self, CliError> {
        if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(CliError::Validation(format!(
                "Refusing to write a secret through {display}: it is a symlink."
            )));
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true);
        if !exists {
            options.create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path).map_err(|e| {
            CliError::Validation(format!(
                "Cannot write to {display}: {e}. Create its directory or fix its permissions, \
                 or pass --env-file to use another file."
            ))
        })?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
            created: !exists,
            written: false,
        })
    }

    /// Replace the file's contents through the handle opened before the
    /// browser. A file that already existed becomes owner-only too: it holds
    /// a secret now.
    fn write(&mut self, display: &str, contents: &str) -> Result<(), CliError> {
        let io =
            |e: std::io::Error| CliError::Other(anyhow::anyhow!("Could not write {display}: {e}"));
        self.file.set_len(0).map_err(io)?;
        self.file.seek(std::io::SeekFrom::Start(0)).map_err(io)?;
        self.file.write_all(contents.as_bytes()).map_err(io)?;
        self.file.flush().map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = self
                .file
                .set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        self.written = true;
        Ok(())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.created && !self.written {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// ── Git ──────────────────────────────────────────────────────────────

/// The repository this runs in, if any. Detected once per run.
struct Git {
    in_repo: bool,
}

impl Git {
    fn detect() -> Self {
        Self {
            in_repo: git(&["rev-parse", "--is-inside-work-tree"])
                .is_some_and(|out| out.status.success()),
        }
    }

    /// Whether git tracks `path`. `None` when git is missing or this is not
    /// a repository, in which case there is nothing to refuse.
    fn tracks(&self, path: &Path) -> Option<bool> {
        self.query(&["ls-files", "--error-unmatch", "--"], path)
    }

    /// Whether git already ignores `path`; `None` outside a repository.
    fn ignores(&self, path: &Path) -> Option<bool> {
        self.query(&["check-ignore", "-q", "--"], path)
    }

    fn query(&self, args: &[&str], path: &Path) -> Option<bool> {
        if !self.in_repo {
            return None;
        }
        let mut args = args.to_vec();
        args.push(path.to_str()?);
        Some(git(&args)?.status.success())
    }
}

fn git(args: &[&str]) -> Option<std::process::Output> {
    Command::new("git").args(args).output().ok()
}

/// The pattern that ignores exactly this file from the `.gitignore` in the
/// working directory, or `None` when the file is not under it.
fn gitignore_entry(env_file: &Path) -> Option<String> {
    let root = std::env::current_dir().ok()?.canonicalize().ok()?;
    let parent = env_file.parent()?.canonicalize().ok()?;
    let relative = parent.strip_prefix(&root).ok()?.join(env_file.file_name()?);
    Some(format!("/{}", relative.to_str()?.replace('\\', "/")))
}

fn append_gitignore(entry: &str) -> Result<(), CliError> {
    let existing = std::fs::read_to_string(".gitignore").unwrap_or_default();
    let mut text = existing.clone();
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    if !existing.contains(GITIGNORE_NOTE.trim_end()) {
        text.push_str(GITIGNORE_NOTE);
    }
    text.push_str(entry);
    text.push('\n');
    std::fs::write(".gitignore", text)
        .map_err(|e| CliError::Other(anyhow::anyhow!("Could not update .gitignore: {e}")))
}

/// Ignore the env file in git unless git already does. `Ok(true)` when
/// `.gitignore` was changed.
fn ensure_ignored(git: &Git, env_file: &Path) -> Result<bool, CliError> {
    if git.ignores(env_file) != Some(false) {
        return Ok(false);
    }
    match gitignore_entry(env_file) {
        Some(entry) => append_gitignore(&entry).map(|()| true),
        None => Ok(false),
    }
}

// ── The account ──────────────────────────────────────────────────────

/// The stored sign-in's access token, if there is one.
fn stored_access_token() -> Option<String> {
    let raw = active_store().get(CLI_NAME, SCHEME).ok().flatten()?;
    let token = TokenBundle::parse_or_raw(&raw).access_token;
    (!token.is_empty()).then_some(token)
}

fn signed_in() -> bool {
    stored_access_token().is_some()
}

/// Where the API is for this project: `--base-url`, `ELEVENLABS_BASE_URL` or
/// the stored residency, else the global host.
fn api_base(ctx: &AppContext) -> String {
    ctx.base_url_override()
        .map(|base| base.trim_end_matches('/').to_string())
        .unwrap_or_else(|| settings::base_url_for(&settings::read_residency()).to_string())
}

/// The OAuth token endpoint follows a loopback `--base-url` so the whole flow
/// can run against a local backend; otherwise it stays on production, as the
/// generated sign-in pins it.
fn token_url_for(base_url_override: Option<&str>) -> String {
    match base_url_override.and_then(loopback_base) {
        Some(base) => format!("{base}/v1/oauth/token"),
        None => TOKEN_URL.to_string(),
    }
}

/// Where the sign-in's token came from, and so where it can be checked: the
/// local backend when `--base-url` is loopback, else the OAuth host.
fn oauth_api_base(base_url_override: Option<&str>) -> String {
    base_url_override
        .and_then(loopback_base)
        .unwrap_or_else(|| OAUTH_API_BASE.to_string())
}

fn loopback_base(base: &str) -> Option<String> {
    let url = reqwest::Url::parse(base).ok()?;
    let host = url.host_str()?;
    let is_loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1");
    is_loopback.then(|| base.trim_end_matches('/').to_string())
}

fn http_client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| CliError::Other(anyhow::anyhow!("build HTTP client: {e}")))
}

const ACCOUNT_ATTEMPTS: u32 = 5;
const ACCOUNT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(2);

/// Which account a credential belongs to, asked of the API directly with
/// exactly that credential and nothing else: the CLI's executor would add
/// the stored sign-in or a key from the environment, and this check is
/// about telling the two apart. `None` when the API rejects the credential.
///
/// The response body is never logged: `/v1/user` describes the account.
fn account_for(
    client: &reqwest::Client,
    base: &str,
    header: (&str, &str),
) -> Result<Option<String>, CliError> {
    let url = format!("{base}/v1/user");
    let (name, value) = header;
    // A brand-new account can still be provisioning right after sign-up; the
    // API says so with 202 and is ready within seconds.
    for attempt in 1..=ACCOUNT_ATTEMPTS {
        let response = block_on(client.get(&url).header(name, value).send())
            .map_err(|e| CliError::Other(anyhow::anyhow!("reach {url}: {e}")))?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if status == reqwest::StatusCode::ACCEPTED && attempt < ACCOUNT_ATTEMPTS {
            std::thread::sleep(ACCOUNT_RETRY_DELAY);
            continue;
        }
        if !status.is_success() {
            return Err(CliError::Other(anyhow::anyhow!("{url} answered {status}")));
        }
        let body: Value = block_on(response.json::<Value>())
            .map_err(|e| CliError::Other(anyhow::anyhow!("read {url}: {e}")))?;
        return match body.get("user_id").and_then(Value::as_str) {
            Some(account) => Ok(Some(account.to_string())),
            None => Err(CliError::Other(anyhow::anyhow!(
                "{url} answered without a user id"
            ))),
        };
    }
    Err(CliError::Other(anyhow::anyhow!(
        "{url} kept answering that the account is still being created"
    )))
}

/// Whether `key` opens the same account the stored sign-in does. Both are
/// asked of the host that issued the sign-in.
fn key_belongs_to_signed_in_account(base: &str, key: &str) -> Result<bool, CliError> {
    let Some(token) = stored_access_token() else {
        return Ok(false);
    };
    let client = http_client()?;
    let bearer = format!("Bearer {token}");
    let Some(account) = account_for(&client, base, ("authorization", &bearer))? else {
        return Ok(false);
    };
    Ok(account_for(&client, base, ("xi-api-key", key))?.as_deref() == Some(account.as_str()))
}

/// Handlers run on the framework's runtime, so an async call is driven the
/// way `sdk::block_on` drives SDK calls, minus its SDK error conversion.
fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(future))
}

fn last4(key: &str) -> String {
    key.chars()
        .rev()
        .take(4)
        .collect::<String>()
        .chars()
        .rev()
        .collect()
}

// ── `onboard` ────────────────────────────────────────────────────────

#[derive(Debug)]
struct Plan {
    product: Option<String>,
    env_file: PathBuf,
    env_display: String,
    no_browser: bool,
    replace: bool,
    authorize_url: String,
}

fn plan(matches: &clap::ArgMatches) -> Result<Plan, CliError> {
    let env_display =
        opt_string(matches, "env-file").unwrap_or_else(|| DEFAULT_ENV_FILE.to_string());
    let env_file = PathBuf::from(&env_display);
    let env_file = if env_file.is_absolute() {
        env_file
    } else {
        std::env::current_dir()
            .map_err(|e| CliError::Other(anyhow::anyhow!("current directory: {e}")))?
            .join(env_file)
    };
    let authorize_url = match opt_string(matches, "authorize-url") {
        None => AUTHORIZE_URL.to_string(),
        // Only a local approval page may stand in for production: this is
        // where the developer types their password.
        Some(url) if loopback_base(&url).is_some() => url,
        Some(_) => {
            return Err(CliError::Validation(
                "--authorize-url must point at a local (loopback) approval page.".to_string(),
            ))
        }
    };
    Ok(Plan {
        product: opt_string(matches, "product"),
        env_file,
        env_display,
        no_browser: matches.get_flag("no-browser"),
        replace: matches.get_flag("replace"),
        authorize_url,
    })
}

/// What the approval page needs to know beyond the sign-in itself:
/// `key_handoff` asks it to create a key and copy it, `product` scopes it.
fn handoff_params(plan: &Plan) -> Vec<(String, String)> {
    let mut params = vec![("key_handoff".to_string(), "clipboard".to_string())];
    if let Some(product) = &plan.product {
        params.push(("product".to_string(), product.clone()));
    }
    params
}

/// The sign-in `auth login` runs, plus the approval page's parameters.
fn sign_in_flow(plan: &Plan, token_url: &str) -> PkceLoginFlow {
    let params = handoff_params(plan);
    PkceLoginFlow::new(SCHEME)
        .client_id(CLIENT_ID)
        .authorization_url(&plan.authorize_url)
        .token_url(token_url)
        .scopes(SCOPES.iter().copied())
        .redirect_host(REDIRECT_HOST)
        .redirect_ports(REDIRECT_PORTS)
        .success_redirect_url(SUCCESS_URL)
        .error_redirect_url(ERROR_URL)
        .authorization_params(params)
}

/// Everything the command reports, in one place, so the JSON and the prose
/// cannot disagree.
struct Report {
    signed_in: bool,
    key_status: KeyStatus,
    env_display: String,
    env_file_written: bool,
    gitignore_updated: bool,
    key_last4: Option<String>,
    placeholder_written: bool,
    /// `--replace` was passed but nothing arrived, so the key that was in the
    /// file is still there.
    existing_key_kept: bool,
}

impl Report {
    fn json(&self) -> Value {
        json!({
            "signed_in": self.signed_in,
            "key_status": self.key_status.as_str(),
            "key_reason": self.key_status.reason(),
            "env_file": self.env_display,
            "env_file_written": self.env_file_written,
            "gitignore_updated": self.gitignore_updated,
            "key_last4": self.key_last4,
            "placeholder_written": self.placeholder_written,
            "existing_key_kept": self.existing_key_kept,
            "next": self.key_status.next(),
        })
    }

    fn prose(&self) -> String {
        let mut lines = vec![];
        match &self.key_status {
            KeyStatus::Created => {
                lines.push(format!(
                    "Signed in. An API key ending in {} is in {}, and your clipboard was cleared.",
                    self.key_last4.as_deref().unwrap_or("????"),
                    self.env_display
                ));
                if self.gitignore_updated {
                    lines.push(format!("Added {} to .gitignore.", self.env_display));
                }
                lines.push(
                    "Load that file the way your app loads its environment and you are ready \
                     to make requests."
                        .to_string(),
                );
            }
            KeyStatus::NotAvailable | KeyStatus::NotPermitted => {
                lines.push(
                    "Signed in, but the approval page could not create an API key for this \
                     account."
                        .to_string(),
                );
                lines.push(format!(
                    "Create one on the API keys page and paste it into {}: {API_KEYS_PAGE_URL}",
                    self.env_display
                ));
            }
            KeyStatus::Failed(reason) if reason == COULD_NOT_VERIFY => {
                lines.push(
                    "Signed in, and a key is on your clipboard, but the API could not be reached \
                     to check it."
                        .to_string(),
                );
                lines.push(format!(
                    "Paste it after `{API_KEY_ENV}=` in {} yourself. Never paste it into a chat.",
                    self.env_display
                ));
            }
            KeyStatus::NoKey | KeyStatus::ClipboardInvalid | KeyStatus::Failed(_) => {
                lines.push("Signed in, but no API key arrived from the approval page.".to_string());
                if let Some(reason) = self.key_status.reason() {
                    lines.push(format!("The page reported: {reason}."));
                }
                lines.push(format!(
                    "Click \"Copy key\" on the approval page, or create a key at \
                     {API_KEYS_PAGE_URL}, and paste it after `{API_KEY_ENV}=` in {}. Never paste \
                     it into a chat.",
                    self.env_display
                ));
            }
        }
        if self.placeholder_written {
            lines.push(format!(
                "{} has an empty `{API_KEY_ENV}=` line waiting for it.",
                self.env_display
            ));
        }
        if self.existing_key_kept {
            lines.push(format!(
                "The key that was already in {} was left in place.",
                self.env_display
            ));
        }
        lines.join("\n")
    }
}

/// Turn what the clipboard held into a stored key or a placeholder.
///
/// Order matters: the key is checked, then written, and only then cleared
/// from the clipboard, so a check that cannot be made or a write that fails
/// never loses the only copy. A key that is not this account's is left where
/// it was: it was there before this command ran.
fn finish(
    plan: &Plan,
    existing: Option<&str>,
    probe: &mut Probe,
    git: &Git,
    clipboard: &mut dyn Clipboard,
    key_is_ours: &dyn Fn(&str) -> Result<bool, CliError>,
) -> Result<Report, CliError> {
    let contents = existing.unwrap_or("");
    let mut report = Report {
        signed_in: true,
        key_status: KeyStatus::NoKey,
        env_display: plan.env_display.clone(),
        env_file_written: false,
        gitignore_updated: false,
        key_last4: None,
        placeholder_written: false,
        existing_key_kept: false,
    };
    match classify(clipboard.read().as_deref()) {
        Clip::Key(key) => match key_is_ours(&key) {
            Ok(true) => {
                probe.write(&plan.env_display, &with_key(contents, &key))?;
                clipboard.clear();
                report.key_status = KeyStatus::Created;
                report.env_file_written = true;
                report.key_last4 = Some(last4(&key));
            }
            Ok(false) => report.key_status = KeyStatus::ClipboardInvalid,
            Err(_) => report.key_status = KeyStatus::Failed(COULD_NOT_VERIFY.to_string()),
        },
        Clip::Note(status) => {
            clipboard.clear();
            report.key_status = status;
        }
        Clip::Nothing => {}
    }
    if report.key_status != KeyStatus::Created {
        match file_key(contents) {
            None => {
                let note = match report.key_status {
                    KeyStatus::NotAvailable | KeyStatus::NotPermitted => LEGACY_PLACEHOLDER_NOTE,
                    _ => PLACEHOLDER_NOTE,
                };
                probe.write(&plan.env_display, &with_placeholder(contents, note))?;
                report.env_file_written = true;
                report.placeholder_written = true;
            }
            Some(key) if !key.is_empty() => report.existing_key_kept = true,
            Some(_) => {}
        }
    }
    if report.env_file_written {
        report.gitignore_updated = ensure_ignored(git, &plan.env_file)?;
    }
    Ok(report)
}

/// The runtime's sign-in names `auth login` in its timeout advice; here the
/// command to run again is this one.
fn describe_sign_in_error(error: CliError) -> CliError {
    match error {
        CliError::Auth(message) if message.contains("Timed out") => CliError::Auth(
            "The browser approval did not finish in time. Nothing was stored; run \
             `elevenlabs onboard` again once you have signed in, or pass --no-browser to open \
             the page yourself."
                .to_string(),
        ),
        other => other,
    }
}

// ── Where the browser is ─────────────────────────────────────────────

/// Whether a browser this process can open would land on this machine, so
/// its redirect and its clipboard reach us. False over SSH, inside a
/// container or a cloud agent, and on a Linux box with no display; true on
/// macOS and Windows, and on Linux with a display or under WSL, where the
/// Windows browser and clipboard are bridged in.
fn browser_reachable_in(
    os: &str,
    var: &dyn Fn(&str) -> Option<String>,
    in_container: bool,
) -> bool {
    let set = |name: &str| var(name).is_some_and(|v| !v.trim().is_empty());
    if set("SSH_CONNECTION") || set("SSH_TTY") || set("SSH_CLIENT") {
        return false;
    }
    if in_container || set("CODESPACES") || set("REMOTE_CONTAINERS") {
        return false;
    }
    match os {
        "linux" => set("WSL_DISTRO_NAME") || set("DISPLAY") || set("WAYLAND_DISPLAY"),
        _ => true,
    }
}

fn in_container() -> bool {
    Path::new("/.dockerenv").exists()
        || std::fs::read_to_string("/proc/1/cgroup")
            .map(|c| c.contains("docker") || c.contains("containerd") || c.contains("kubepods"))
            .unwrap_or(false)
}

fn browser_reachable() -> bool {
    browser_reachable_in(
        std::env::consts::OS,
        &|name| std::env::var(name).ok(),
        in_container(),
    )
}

const NO_BROWSER_HERE: &str = "\
No browser can reach this machine (an SSH session, a container or a cloud agent), so the \
approval page cannot hand a key to this command. Create a key at \
https://elevenlabs.io/app/settings/api-keys and expose it as ELEVENLABS_API_KEY the way you \
manage secrets here, then run `elevenlabs onboard status`. If your browser does reach this \
machine (for example through port forwarding), pass --no-browser to open the link yourself.";

fn handle_onboard(matches: &clap::ArgMatches, ctx: &AppContext) -> Result<(), CliError> {
    let _scope = api::command_scope("onboard");
    let plan = plan(matches)?;
    if !plan.no_browser && !browser_reachable() {
        return Err(CliError::Validation(NO_BROWSER_HERE.to_string()));
    }
    let existing = read_env_file(&plan.env_file, &plan.env_display)?;
    let contents = existing.as_deref().unwrap_or("");

    if let Some(key) = file_key(contents).filter(|k| !k.is_empty()) {
        if !plan.replace {
            return Err(CliError::Validation(format!(
                "{} already sets {API_KEY_ENV} (ending in {}). Run `elevenlabs onboard status` to \
                 check it, or pass --replace to sign in and store a new key over it.",
                plan.env_display,
                last4(&key)
            )));
        }
    }
    let git = Git::detect();
    if git.tracks(&plan.env_file) == Some(true) {
        return Err(CliError::Validation(format!(
            "{} is tracked by git, so a secret must not go there. Pass --env-file with a file git \
             does not track, such as .env.local.",
            plan.env_display
        )));
    }

    if dry_run_flag(matches) {
        println!(
            "[DRY RUN] Would sign in at {} asking for {} and write the key to {}.",
            plan.authorize_url,
            plan.product.as_deref().unwrap_or("the default permissions"),
            plan.env_display
        );
        return Ok(());
    }

    let mut probe = Probe::open(&plan.env_file, &plan.env_display, existing.is_some())?;
    let token_url = token_url_for(ctx.base_url_override());
    let flow = sign_in_flow(&plan, &token_url);

    eprintln!("Sign in to ElevenLabs in the browser, or create an account, then click Authorize.");
    eprintln!("That approval is the only step outside this terminal. The page creates an API key");
    eprintln!(
        "for this project; this command stores it in {} and never shows it.",
        plan.env_display
    );
    eprintln!();
    flow.run(&LoginContext {
        cli_name: CLI_NAME.to_string(),
        no_browser: plan.no_browser,
    })
    .map_err(describe_sign_in_error)?;

    let base = oauth_api_base(ctx.base_url_override());
    let mut clipboard = SystemClipboard::open();
    let report = finish(
        &plan,
        existing.as_deref(),
        &mut probe,
        &git,
        &mut clipboard,
        &|key| key_belongs_to_signed_in_account(&base, key),
    )?;
    emit(matches, &report.json(), &report.prose());
    Ok(())
}

// ── `onboard status` ─────────────────────────────────────────────────

fn handle_status(matches: &clap::ArgMatches, ctx: &AppContext) -> Result<(), CliError> {
    let _scope = api::command_scope("onboard.status");
    let env_display =
        opt_string(matches, "env-file").unwrap_or_else(|| DEFAULT_ENV_FILE.to_string());
    let existing = read_env_file(Path::new(&env_display), &env_display)?;
    let from_file = file_key(existing.as_deref().unwrap_or("")).filter(|k| !k.is_empty());
    let from_env = std::env::var(API_KEY_ENV)
        .ok()
        .filter(|k| !k.trim().is_empty());
    let (key, source) = match (from_env, from_file) {
        // Env files are loaded into the environment at startup (`.env.local`
        // by `register`, `.env` by the runtime), so a key that matches the
        // file's is the file's.
        (Some(env), Some(file)) if env == file => (Some(file), "env_file"),
        (Some(key), _) => (Some(key), "env"),
        (None, Some(key)) => (Some(key), "env_file"),
        (None, None) => (None, "none"),
    };
    let valid = match &key {
        Some(key) => http_client()
            .and_then(|client| account_for(&client, &api_base(ctx), ("xi-api-key", key)))
            .ok()
            .map(|account| account.is_some()),
        None => None,
    };
    let browser = browser_reachable();
    let facts = json!({
        "signed_in": signed_in(),
        "browser_reachable": browser,
        "env_file": env_display,
        "env_file_exists": existing.is_some(),
        "api_key_present": key.is_some(),
        "api_key_source": source,
        "api_key_valid": valid,
        "api_key_last4": key.as_deref().map(last4),
    });
    let key_line = match (&key, valid) {
        (None, _) => "none".to_string(),
        (Some(k), Some(true)) => format!("ending in {}, from the {source}, works", last4(k)),
        (Some(k), Some(false)) => {
            format!(
                "ending in {}, from the {source}, rejected by the API",
                last4(k)
            )
        }
        (Some(k), None) => {
            format!(
                "ending in {}, from the {source}, could not be checked",
                last4(k)
            )
        }
    };
    let prose = [
        format!("Signed in:        {}", yes_no(facts["signed_in"].as_bool())),
        format!(
            "Browser:          {}",
            if browser {
                "can reach this machine"
            } else {
                "cannot reach this machine (remote)"
            }
        ),
        format!(
            "Env file:         {env_display}{}",
            if existing.is_some() { "" } else { " (missing)" }
        ),
        format!("API key:          {key_line}"),
    ]
    .join("\n");
    emit(matches, &facts, &prose);
    Ok(())
}

fn yes_no(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    }
}

/// JSON under `--format json`, `ELEVENLABS_OUTPUT`, or when stdout is not a
/// terminal, the same way the framework decides for every other command.
fn emit(matches: &clap::ArgMatches, machine: &Value, human: &str) {
    let machine_readable = OutputPipeline::from_matches(matches, CLI_NAME)
        .map(|pipeline| pipeline.format.is_machine_readable())
        .unwrap_or(false);
    if machine_readable {
        println!(
            "{}",
            serde_json::to_string_pretty(machine).expect("report serializes")
        );
    } else {
        println!("{human}");
    }
}

// ── `.env.local` ─────────────────────────────────────────────────────

/// Let every command find the key `onboard` wrote. Nothing that loads `.env`
/// overrides a variable that is already set (`residency::register` and the
/// framework's own pass both go through dotenvy), so loading `.env.local`
/// before them, which `workflow::register` orders, gives it precedence, the
/// way Next.js and Vite order the two. Only the key is taken: the framework
/// filters `.env` for transport settings (`ELEVENLABS_BASE_URL` and friends),
/// and that filtering is not reachable from here, so nothing else may come in.
fn load_env_local_key() {
    if std::env::var_os(API_KEY_ENV).is_some_and(|v| !v.is_empty()) {
        return;
    }
    let Ok(entries) = dotenvy::from_filename_iter(DEFAULT_ENV_FILE) else {
        return;
    };
    for (key, value) in entries.flatten() {
        if key == API_KEY_ENV && !value.trim().is_empty() {
            std::env::set_var(API_KEY_ENV, value);
            return;
        }
    }
}

// ── Registration ─────────────────────────────────────────────────────

const ABOUT: &str = "Sign in and put a working ElevenLabs API key in this project";

const LONG_ABOUT: &str = "\
Sign in to ElevenLabs in the browser and store an API key for this project, in one step.

The approval page creates a key scoped to the product you name (or with the default \
permissions when you name none) and hands it to this command, which writes it to the env \
file, adds that file to .gitignore, and clears your clipboard. The key is never printed.

Output is JSON when piped or with --format json. `key_status` says what happened and `next` \
says what to do: `none` when the key is in place, `paste_key` when it has to be pasted into \
the env file by hand, `legacy` when this account cannot create keys this way.";

fn env_file_arg() -> clap::Arg {
    clap::Arg::new("env-file")
        .long("env-file")
        .value_name("PATH")
        .help("The env file holding ELEVENLABS_API_KEY (default: .env.local in the current directory)")
}

fn onboard_command() -> clap::Command {
    clap::Command::new("onboard")
        .about(ABOUT)
        .long_about(LONG_ABOUT)
        .args_conflicts_with_subcommands(true)
        .arg(
            clap::Arg::new("product")
                .long("product")
                .value_name("SLUG")
                .value_parser(PRODUCTS.to_vec())
                .help("Scope the key to one product, named like its skill (e.g. text-to-speech)"),
        )
        .arg(env_file_arg())
        .arg(
            clap::Arg::new("no-browser")
                .long("no-browser")
                .action(clap::ArgAction::SetTrue)
                .help("Print the sign-in URL instead of opening a browser (also skips the remote-machine check)"),
        )
        .arg(
            clap::Arg::new("replace")
                .long("replace")
                .action(clap::ArgAction::SetTrue)
                .help("Store a new key even if the env file already has one"),
        )
        .arg(
            clap::Arg::new("authorize-url")
                .long("authorize-url")
                .value_name("URL")
                .hide(true)
                .help("A local approval page to open instead of production (development only)"),
        )
        .subcommand(
            clap::Command::new("status")
                .about("Report whether this project is signed in, has a working API key, and can reach a browser")
                .arg(env_file_arg()),
        )
}

fn dispatch(matches: &clap::ArgMatches, ctx: &AppContext) -> Result<(), CliError> {
    match matches.subcommand() {
        Some(("status", sub)) => handle_status(sub, ctx),
        _ => handle_onboard(matches, ctx),
    }
}

/// Register `onboard` and `onboard status`, and make `.env.local` visible to
/// every command. Must run before anything else loads `.env`.
pub fn register(app: CliApp) -> CliApp {
    load_env_local_key();
    app.command(
        onboard_command(),
        Box::new(|matches, ctx| dispatch(matches, downcast_ctx(ctx)?)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── main.rs drift ───────────────────────────────────────────────

    #[test]
    fn main_rs_declares_the_same_sign_in() {
        let main_rs = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/cli/elevenlabs/main.rs"
        ))
        .expect("main.rs is next to this module");
        for literal in [
            CLIENT_ID,
            AUTHORIZE_URL,
            TOKEN_URL,
            REDIRECT_HOST,
            SUCCESS_URL,
            ERROR_URL,
        ] {
            assert!(
                main_rs.contains(&format!("\"{literal}\"")),
                "main.rs no longer pins {literal}"
            );
        }
        let ports = format!(
            "redirect_ports([{}])",
            REDIRECT_PORTS
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        assert!(main_rs.contains(&ports), "main.rs no longer pins {ports}");
        let scopes = SCOPES
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(
            main_rs.contains(&format!("scopes([{scopes}])")),
            "main.rs scopes differ from SCOPES"
        );
        assert!(
            TOKEN_URL.starts_with(OAUTH_API_BASE),
            "the account check must ask the host that issues the token"
        );
    }

    // ── the clipboard ───────────────────────────────────────────────

    #[test]
    fn a_key_is_recognized_with_and_without_a_residency_suffix() {
        assert!(looks_like_key(
            "sk_0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(looks_like_key(
            "sk_0123456789abcdef0123456789abcdef_residency_eu"
        ));
        assert!(!looks_like_key(
            "sk_0123456789abcdef0123456789abcdef_residency_"
        ));
        assert!(!looks_like_key("sk_short"));
        assert!(!looks_like_key("0123456789abcdef0123456789abcdef01234567"));
        assert!(!looks_like_key(
            "sk_0123456789abcdef0123456789abcdef trailing"
        ));
    }

    #[test]
    fn the_clipboard_is_classified() {
        let key = "sk_0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            classify(Some(&format!("  {key}\n"))),
            Clip::Key(key.to_string())
        );
        assert_eq!(
            classify(Some("elevenlabs:not_available")),
            Clip::Note(KeyStatus::NotAvailable)
        );
        assert_eq!(
            classify(Some("elevenlabs:not_permitted")),
            Clip::Note(KeyStatus::NotPermitted)
        );
        assert_eq!(
            classify(Some("elevenlabs:failed:too_many_api_keys")),
            Clip::Note(KeyStatus::Failed("too_many_api_keys".to_string()))
        );
        assert_eq!(
            classify(Some("elevenlabs:something_else")),
            Clip::Note(KeyStatus::Failed("something_else".to_string()))
        );
        assert_eq!(
            classify(Some("some text the user had copied")),
            Clip::Nothing
        );
        assert_eq!(classify(Some("")), Clip::Nothing);
        assert_eq!(classify(None), Clip::Nothing);
    }

    #[test]
    fn a_note_that_is_not_a_short_code_is_ignored() {
        // Printed back to the user, so nothing that could pose as output.
        assert_eq!(
            classify(Some("elevenlabs:failed:x\n\u{1b}[2KSigned in.")),
            Clip::Nothing
        );
        assert_eq!(classify(Some("elevenlabs:")), Clip::Nothing);
        assert_eq!(
            classify(Some(&format!("elevenlabs:{}", "a".repeat(65)))),
            Clip::Nothing
        );
    }

    #[test]
    fn each_status_tells_the_skill_what_to_do_next() {
        assert_eq!(KeyStatus::Created.next(), "none");
        assert_eq!(KeyStatus::NoKey.next(), "paste_key");
        assert_eq!(KeyStatus::ClipboardInvalid.next(), "paste_key");
        assert_eq!(KeyStatus::Failed("x".into()).next(), "paste_key");
        assert_eq!(KeyStatus::NotAvailable.next(), "legacy");
        assert_eq!(KeyStatus::NotPermitted.next(), "legacy");
    }

    // ── the env file ────────────────────────────────────────────────

    #[test]
    fn the_key_line_is_found_in_its_common_spellings() {
        assert_eq!(file_key("ELEVENLABS_API_KEY=sk_1\n"), Some("sk_1".into()));
        assert_eq!(
            file_key("export ELEVENLABS_API_KEY = \"sk_1\"\n"),
            Some("sk_1".into())
        );
        assert_eq!(file_key("ELEVENLABS_API_KEY=\n"), Some(String::new()));
        assert_eq!(file_key("ELEVENLABS_API_KEY_OLD=sk_1\n"), None);
        assert_eq!(file_key("# ELEVENLABS_API_KEY=sk_1\n"), None);
        assert_eq!(file_key("OTHER=1\n"), None);
        assert_eq!(
            file_key("\u{feff}ELEVENLABS_API_KEY=sk_1"),
            Some("sk_1".into())
        );
    }

    #[test]
    fn with_key_appends_when_absent_and_replaces_in_place_when_present() {
        assert_eq!(with_key("", "sk_new"), "ELEVENLABS_API_KEY=sk_new\n");
        assert_eq!(
            with_key("A=1", "sk_new"),
            "A=1\nELEVENLABS_API_KEY=sk_new\n"
        );
        assert_eq!(
            with_key("A=1\r\nB=2\r\n", "sk_new"),
            "A=1\r\nB=2\r\nELEVENLABS_API_KEY=sk_new\r\n"
        );
        assert_eq!(
            with_key("A=1\nELEVENLABS_API_KEY=old\nB=2\n", "sk_new"),
            "A=1\nELEVENLABS_API_KEY=sk_new\nB=2\n"
        );
        assert_eq!(
            with_key("\u{feff}ELEVENLABS_API_KEY=", "sk_new"),
            "\u{feff}ELEVENLABS_API_KEY=sk_new"
        );
    }

    #[test]
    fn a_placeholder_is_added_once_and_replaced_by_a_real_key() {
        let once = with_placeholder("A=1\n", PLACEHOLDER_NOTE);
        assert!(once.ends_with("ELEVENLABS_API_KEY=\n"));
        assert!(once.contains(PLACEHOLDER_NOTE));
        assert_eq!(
            with_placeholder(&once, PLACEHOLDER_NOTE),
            once,
            "a second run must not stack notes"
        );
        let filled = with_key(&once, "sk_new");
        assert!(filled.ends_with("ELEVENLABS_API_KEY=sk_new\n"));
        assert_eq!(filled.matches("ELEVENLABS_API_KEY").count(), 1);
    }

    #[test]
    fn last4_handles_short_values() {
        assert_eq!(last4("sk_abcd"), "abcd");
        assert_eq!(last4("ab"), "ab");
    }

    #[test]
    fn a_probe_that_created_the_file_removes_it_unless_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env.local");
        let probe = Probe::open(&path, ".env.local", false).unwrap();
        assert!(path.exists());
        drop(probe);
        assert!(
            !path.exists(),
            "an untouched file this run created is removed"
        );

        let mut probe = Probe::open(&path, ".env.local", false).unwrap();
        probe.write(".env.local", "A=1\n").unwrap();
        drop(probe);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=1\n");
    }

    #[test]
    fn a_probe_on_an_existing_file_leaves_it_alone_until_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env");
        std::fs::write(&path, "A=1\nB=2\n").unwrap();
        let probe = Probe::open(&path, ".env", true).unwrap();
        drop(probe);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "A=1\nB=2\n");
    }

    // ── the hand-off ────────────────────────────────────────────────

    struct FakeClipboard {
        text: Option<String>,
        cleared: bool,
    }

    impl Clipboard for FakeClipboard {
        fn read(&mut self) -> Option<String> {
            self.text.clone()
        }
        fn clear(&mut self) {
            self.cleared = true;
        }
    }

    const NO_GIT: Git = Git { in_repo: false };

    fn plan_in(dir: &Path) -> Plan {
        Plan {
            product: Some("text-to-speech".into()),
            env_file: dir.join(".env.local"),
            env_display: ".env.local".into(),
            no_browser: false,
            replace: false,
            authorize_url: AUTHORIZE_URL.into(),
        }
    }

    /// Run `finish` the way `handle_onboard` does, with the file in the state
    /// `existing` describes.
    fn run_finish(
        plan: &Plan,
        existing: Option<&str>,
        clipboard: &mut FakeClipboard,
        key_is_ours: &dyn Fn(&str) -> Result<bool, CliError>,
    ) -> Report {
        if let Some(contents) = existing {
            std::fs::write(&plan.env_file, contents).unwrap();
        }
        let mut probe = Probe::open(&plan.env_file, &plan.env_display, existing.is_some()).unwrap();
        finish(plan, existing, &mut probe, &NO_GIT, clipboard, key_is_ours).unwrap()
    }

    #[test]
    fn a_key_for_this_account_is_stored_and_the_clipboard_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_in(dir.path());
        let key = "sk_0123456789abcdef0123456789abcdef01234567";
        let mut clipboard = FakeClipboard {
            text: Some(key.into()),
            cleared: false,
        };
        let report = run_finish(&plan, None, &mut clipboard, &|k| Ok(k == key));
        assert_eq!(report.key_status, KeyStatus::Created);
        assert_eq!(report.key_last4.as_deref(), Some("4567"));
        assert!(clipboard.cleared);
        assert_eq!(
            std::fs::read_to_string(&plan.env_file).unwrap(),
            format!("ELEVENLABS_API_KEY={key}\n")
        );
        assert!(
            !report.json().to_string().contains(key),
            "the key never appears in the report"
        );
    }

    #[test]
    fn a_key_for_another_account_is_left_on_the_clipboard_and_a_placeholder_written() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_in(dir.path());
        let mut clipboard = FakeClipboard {
            text: Some("sk_0123456789abcdef0123456789abcdef01234567".into()),
            cleared: false,
        };
        let report = run_finish(&plan, None, &mut clipboard, &|_| Ok(false));
        assert_eq!(report.key_status, KeyStatus::ClipboardInvalid);
        assert!(
            !clipboard.cleared,
            "a key that is not ours was there before us"
        );
        assert!(report.placeholder_written);
        let written = std::fs::read_to_string(&plan.env_file).unwrap();
        assert!(written.ends_with("ELEVENLABS_API_KEY=\n"));
        assert!(!written.contains("sk_"));
    }

    #[test]
    fn a_key_that_cannot_be_checked_stays_on_the_clipboard() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_in(dir.path());
        let mut clipboard = FakeClipboard {
            text: Some("sk_0123456789abcdef0123456789abcdef01234567".into()),
            cleared: false,
        };
        let report = run_finish(&plan, None, &mut clipboard, &|_| {
            Err(CliError::Other(anyhow::anyhow!("offline")))
        });
        assert_eq!(
            report.key_status,
            KeyStatus::Failed(COULD_NOT_VERIFY.into())
        );
        assert_eq!(report.json()["next"], "paste_key");
        assert!(!clipboard.cleared, "the only copy of the key is kept");
        assert!(report.placeholder_written);
        assert!(report.prose().contains("on your clipboard"));
    }

    #[test]
    fn an_empty_clipboard_leaves_a_placeholder_and_the_users_clipboard_alone() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_in(dir.path());
        let mut clipboard = FakeClipboard {
            text: Some("unrelated text".into()),
            cleared: false,
        };
        let report = run_finish(&plan, Some("A=1\n"), &mut clipboard, &|_| Ok(true));
        assert_eq!(report.key_status, KeyStatus::NoKey);
        assert_eq!(report.json()["next"], "paste_key");
        assert!(!clipboard.cleared, "text that is not ours is not touched");
        let written = std::fs::read_to_string(&plan.env_file).unwrap();
        assert!(written.starts_with("A=1\n"));
        assert!(written.ends_with("ELEVENLABS_API_KEY=\n"));
    }

    #[test]
    fn the_pages_note_is_reported_and_routes_to_the_legacy_flow() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_in(dir.path());
        let mut clipboard = FakeClipboard {
            text: Some("elevenlabs:not_permitted".into()),
            cleared: false,
        };
        let report = run_finish(&plan, None, &mut clipboard, &|_| Ok(true));
        assert_eq!(report.key_status, KeyStatus::NotPermitted);
        assert_eq!(report.json()["next"], "legacy");
        assert!(clipboard.cleared, "the note is ours to clean up");
        let written = std::fs::read_to_string(&plan.env_file).unwrap();
        assert!(
            written.contains("workspace administrator") && !written.contains("Copy key"),
            "the legacy placeholder must not point at a button that is not there: {written}"
        );
    }

    #[test]
    fn an_existing_placeholder_is_not_duplicated_when_nothing_arrives() {
        let dir = tempfile::tempdir().unwrap();
        let plan = plan_in(dir.path());
        let existing = with_placeholder("", PLACEHOLDER_NOTE);
        let mut clipboard = FakeClipboard {
            text: None,
            cleared: false,
        };
        let report = run_finish(&plan, Some(&existing), &mut clipboard, &|_| Ok(true));
        assert!(!report.placeholder_written);
        assert!(!report.env_file_written);
        assert_eq!(std::fs::read_to_string(&plan.env_file).unwrap(), existing);
    }

    #[test]
    fn with_replace_and_nothing_arriving_the_old_key_is_kept_and_said_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut plan = plan_in(dir.path());
        plan.replace = true;
        let existing = "ELEVENLABS_API_KEY=sk_old\n";
        let mut clipboard = FakeClipboard {
            text: None,
            cleared: false,
        };
        let report = run_finish(&plan, Some(existing), &mut clipboard, &|_| Ok(true));
        assert!(report.existing_key_kept);
        assert!(!report.env_file_written);
        assert_eq!(std::fs::read_to_string(&plan.env_file).unwrap(), existing);
        assert!(report.prose().contains("left in place"));
    }

    // ── the sign-in ─────────────────────────────────────────────────

    #[test]
    fn the_token_endpoint_follows_only_a_loopback_base_url() {
        assert_eq!(token_url_for(None), TOKEN_URL);
        assert_eq!(
            token_url_for(Some("https://api.eu.residency.elevenlabs.io")),
            TOKEN_URL
        );
        assert_eq!(
            token_url_for(Some("http://localhost:8000/")),
            "http://localhost:8000/v1/oauth/token"
        );
        assert_eq!(
            token_url_for(Some("http://127.0.0.1:8000")),
            "http://127.0.0.1:8000/v1/oauth/token"
        );
    }

    #[test]
    fn the_account_check_asks_the_host_that_issued_the_sign_in() {
        assert_eq!(oauth_api_base(None), OAUTH_API_BASE);
        assert_eq!(
            oauth_api_base(Some("https://api.eu.residency.elevenlabs.io")),
            OAUTH_API_BASE
        );
        assert_eq!(
            oauth_api_base(Some("http://localhost:8000")),
            "http://localhost:8000"
        );
    }

    #[test]
    fn the_page_is_asked_for_a_clipboard_handoff_and_nothing_else() {
        let mut plan = plan_in(Path::new("."));
        plan.product = None;
        assert_eq!(
            handoff_params(&plan),
            vec![("key_handoff".to_string(), "clipboard".to_string())]
        );
        plan.product = Some("music".into());
        plan.no_browser = true;
        let params = handoff_params(&plan);
        assert_eq!(
            params[0].1, "clipboard",
            "--no-browser changes nothing here"
        );
        assert_eq!(params[1], ("product".to_string(), "music".to_string()));
        assert!(params.iter().all(|(k, _)| k != "cli_version"));
    }

    #[test]
    fn a_browser_reaches_a_laptop_but_not_a_remote_box() {
        let none = |_: &str| None;
        let ssh = |name: &str| (name == "SSH_CONNECTION").then(|| "1.2.3.4 22".to_string());
        let display = |name: &str| (name == "DISPLAY").then(|| ":0".to_string());
        let wsl = |name: &str| (name == "WSL_DISTRO_NAME").then(|| "Ubuntu".to_string());
        let codespace = |name: &str| (name == "CODESPACES").then(|| "true".to_string());
        assert!(browser_reachable_in("macos", &none, false));
        assert!(browser_reachable_in("windows", &none, false));
        assert!(!browser_reachable_in("macos", &ssh, false));
        assert!(!browser_reachable_in("linux", &none, false), "no display");
        assert!(browser_reachable_in("linux", &display, false));
        assert!(browser_reachable_in("linux", &wsl, false));
        assert!(!browser_reachable_in("linux", &display, true), "container");
        assert!(!browser_reachable_in("linux", &codespace, false));
    }

    #[test]
    fn the_sign_in_timeout_names_this_command() {
        let described = describe_sign_in_error(CliError::Auth(
            "Timed out waiting for the OAuth callback after 300s. Run `auth login` again".into(),
        ));
        assert!(described.to_string().contains("elevenlabs onboard"));
        assert!(!described.to_string().contains("auth login"));
    }

    #[test]
    fn the_report_carries_every_field_the_skill_reads() {
        let report = Report {
            signed_in: true,
            key_status: KeyStatus::Failed("too_many_api_keys".into()),
            env_display: ".env.local".into(),
            env_file_written: true,
            gitignore_updated: false,
            key_last4: None,
            placeholder_written: true,
            existing_key_kept: false,
        };
        let json = report.json();
        for field in [
            "signed_in",
            "key_status",
            "key_reason",
            "env_file",
            "env_file_written",
            "gitignore_updated",
            "key_last4",
            "placeholder_written",
            "existing_key_kept",
            "next",
        ] {
            assert!(json.get(field).is_some(), "missing {field}");
        }
        assert_eq!(json["key_reason"], "too_many_api_keys");
        assert!(report.prose().contains("too_many_api_keys"));
    }

    // ── the command line ────────────────────────────────────────────

    fn matches(args: &[&str]) -> clap::ArgMatches {
        onboard_command()
            .try_get_matches_from(std::iter::once("onboard").chain(args.iter().copied()))
            .expect("arguments parse")
    }

    #[test]
    fn an_unknown_product_is_rejected_by_clap() {
        assert!(onboard_command()
            .try_get_matches_from(["onboard", "--product", "tts"])
            .is_err());
    }

    #[test]
    fn only_a_loopback_approval_page_may_replace_production() {
        assert!(plan(&matches(&[
            "--authorize-url",
            "http://localhost:3000/app/oauth/authorize"
        ]))
        .is_ok());
        let err = plan(&matches(&[
            "--authorize-url",
            "https://elevenlabs.io.evil.example/authorize",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("loopback"));
    }

    #[test]
    fn the_env_file_defaults_to_env_local_in_the_working_directory() {
        let planned = plan(&matches(&[])).unwrap();
        assert_eq!(planned.env_display, ".env.local");
        assert!(planned.env_file.is_absolute());
        assert!(planned.env_file.ends_with(".env.local"));
        assert_eq!(planned.product, None);
        assert_eq!(planned.authorize_url, AUTHORIZE_URL);
    }

    #[test]
    fn status_is_a_subcommand_and_cannot_take_the_parents_flags() {
        assert!(matches(&["status", "--env-file", ".env"])
            .subcommand_matches("status")
            .is_some());
        assert!(onboard_command()
            .try_get_matches_from(["onboard", "--product", "music", "status"])
            .is_err());
    }
}
