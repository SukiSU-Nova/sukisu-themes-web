//! Admin-only inspection of an encrypted theme package.
//!
//! A `.sukisu` package is `SKTH` + 12-byte GCM nonce + AES-256-GCM ciphertext
//! around a ZIP. The manager (ThemePackageCrypto.kt) and `package.rs` share the
//! same key, so the console can decrypt, list, preview images (detected by
//! their content, not their file extension) and edit a JSON entry, then
//! re-encrypt without ever exposing the key to the browser.
//!
//! Every operation re-reads the package from storage; nothing is cached across
//! requests. Edits are validated with `validate_package` before they are
//! written back, and the stored SHA-256/size are refreshed so managers and the
//! catalog see the new bytes.

use std::io::{Cursor, Read, Write};
use std::path::{Component, Path as StdPath, PathBuf};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::Response;
use axum::routing::{get, put};
use axum::{Extension, Json, Router};
use bytes::Bytes;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::accounts::{self, SessionInfo};
use crate::api::{json_body, ApiError, AppState};
use crate::catalog;
use crate::config::{PACKAGE_KEY, PACKAGE_MAGIC};
use crate::models::{Meta, PackageInfo, PendingMeta};
use crate::util::{content_type_for, now_iso, sha256_hex};

type ApiResult<T> = Result<T, ApiError>;

const MAX_ENTRIES: usize = 64;
const MAX_TOTAL_UNCOMPRESSED: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 2 * 1024 * 1024;

pub fn admin_router() -> Router<AppState> {
    Router::new()
        .route("/theme-files/{id}", get(list_theme_files))
        .route("/theme-files/{id}/file", get(read_theme_file))
        .route("/theme-files/{id}/json", put(save_theme_json))
        .route("/theme-files/{id}/download", get(download_theme_files))
        .route("/pending-files/{id}", get(list_pending_files))
        .route("/pending-files/{id}/file", get(read_pending_file))
        .route("/pending-files/{id}/json", put(save_pending_json))
        .route("/pending-files/{id}/download", get(download_pending_files))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetKind {
    Theme,
    Pending,
}

impl TargetKind {
    fn label(self) -> &'static str {
        match self {
            TargetKind::Theme => "theme",
            TargetKind::Pending => "pending",
        }
    }
}

#[derive(Deserialize)]
struct FileQuery {
    path: String,
}

struct Entry {
    name: String,
    data: Vec<u8>,
}

struct Loaded {
    info: TargetInfo,
    entries: Vec<Entry>,
    plain: Vec<u8>,
    raw: Vec<u8>,
    sha256: String,
    size: u64,
    id: String,
    name: String,
    version: i64,
}

enum TargetInfo {
    Theme { meta_path: PathBuf, meta: Meta },
    Pending { directory: PathBuf, meta: PendingMeta },
}

async fn list_theme_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    list_common(&state, TargetKind::Theme, &id).await
}

async fn list_pending_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    list_common(&state, TargetKind::Pending, &id).await
}

async fn read_theme_file(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
) -> ApiResult<Response> {
    read_common(&state, TargetKind::Theme, &id, &query.path).await
}

async fn read_pending_file(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<FileQuery>,
) -> ApiResult<Response> {
    read_common(&state, TargetKind::Pending, &id, &query.path).await
}

async fn save_theme_json(
    State(state): State<AppState>,
    Extension(actor): Extension<SessionInfo>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let value = json_body(body).await?;
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let content = value
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    edit_common(
        &state,
        TargetKind::Theme,
        &id,
        &actor,
        Edit::Json { path, content },
    )
    .await
}

async fn save_pending_json(
    State(state): State<AppState>,
    Extension(actor): Extension<SessionInfo>,
    Path(id): Path<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let value = json_body(body).await?;
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let content = value
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    edit_common(
        &state,
        TargetKind::Pending,
        &id,
        &actor,
        Edit::Json { path, content },
    )
    .await
}

async fn download_theme_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    download_common(&state, TargetKind::Theme, &id).await
}

async fn download_pending_files(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    download_common(&state, TargetKind::Pending, &id).await
}

async fn list_common(state: &AppState, kind: TargetKind, id: &str) -> ApiResult<Json<Value>> {
    let loaded = load_target(state, kind, id).await?;
    Ok(Json(json!({
        "ok": true,
        "kind": loaded.info_kind(),
        "id": loaded.id,
        "name": loaded.name,
        "version": loaded.version,
        "sha256": loaded.sha256,
        "size": loaded.size,
        "files": loaded.entries.iter().map(|entry| json!({
            "name": entry.name,
            "size": entry.data.len(),
            "kind": entry_kind(&entry.name, &entry.data),
        })).collect::<Vec<_>>(),
    })))
}

impl Loaded {
    fn info_kind(&self) -> &'static str {
        match &self.info {
            TargetInfo::Theme { .. } => "theme",
            TargetInfo::Pending { .. } => "pending",
        }
    }
}

async fn read_common(
    state: &AppState,
    kind: TargetKind,
    id: &str,
    path: &str,
) -> ApiResult<Response> {
    let loaded = load_target(state, kind, id).await?;
    let entry = loaded
        .entries
        .iter()
        .find(|entry| entry.name == path)
        .ok_or_else(|| ApiError::not_found("主题包里没有这个文件"))?;
    let content_type = read_content_type(&entry.name, &entry.data);
    // Never let a package entry (HTML/JS/SVG) run as a same-origin document.
    // Those types are only offered as attachments; the console previews text
    // by fetching and rendering it as inert text.
    let active = matches!(
        std::path::Path::new(path)
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .as_deref(),
        Some("html" | "htm" | "svg" | "js" | "mjs")
    );
    let inline = !active
        && (content_type.starts_with("image/")
            || content_type.starts_with("text/")
            || content_type.starts_with("application/json")
            || content_type.starts_with("application/javascript"));
    let disposition = if inline {
        "inline".to_string()
    } else {
        format!(
            "attachment; filename=\"{}\"",
            safe_filename(&entry.name)
        )
    };
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_DISPOSITION, disposition)
        .header(header::CACHE_CONTROL, "private, no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header(header::CONTENT_LENGTH, entry.data.len().to_string())
        .body(Body::from(entry.data.clone()))
        .map_err(ApiError::internal)
}

async fn download_common(state: &AppState, kind: TargetKind, id: &str) -> ApiResult<Response> {
    let loaded = load_target(state, kind, id).await?;
    let filename = format!("{}-decrypted.zip", safe_filename(&loaded.id));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/zip")
        .header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{filename}\""),
        )
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(header::CONTENT_LENGTH, loaded.plain.len().to_string())
        .body(Body::from(loaded.plain))
        .map_err(ApiError::internal)
}

/// Detect the common image formats by content, not by file name. Theme
/// packages store previews without extensions, so extension-based detection
/// would classify them as opaque binaries.
fn image_mime(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some("image/png");
    }
    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if data.len() >= 12 && data.starts_with(b"RIFF") && &data[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    None
}

fn is_json_name(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".json")
}

fn entry_kind(name: &str, data: &[u8]) -> &'static str {
    if image_mime(data).is_some() {
        "image"
    } else if is_json_name(name) {
        "json"
    } else if content_type_for(name).starts_with("text/") {
        "text"
    } else {
        "binary"
    }
}

fn read_content_type(name: &str, data: &[u8]) -> String {
    if let Some(mime) = image_mime(data) {
        // A file that merely looks like an image but is named .html/.svg must
        // still be served as an attachment by the `active` guard below.
        return mime.to_string();
    }
    content_type_for(name)
}

enum Edit {
    Json { path: String, content: String },
}

async fn edit_common(
    state: &AppState,
    kind: TargetKind,
    id: &str,
    actor: &SessionInfo,
    edit: Edit,
) -> ApiResult<Json<Value>> {
    // Serialize with every other theme writer. The rest of the console locks
    // on the bare theme id (upload, approve, delete, rollback), so we must
    // share that key rather than invent a per-route one. Resolve the id from
    // metadata only, then read the package once under the lock.
    let lock_id = lock_key(state, kind, id)?;
    let lock = catalog::theme_mutation_lock(&lock_id);
    let _guard = lock.lock().await;
    let mut loaded = load_target(state, kind, id).await?;
    let (path, action) = match edit {
        Edit::Json { path, content } => {
            if !path.to_ascii_lowercase().ends_with(".json") {
                return Err(ApiError::bad("只有 JSON 文件可以在线编辑"));
            }
            if content.len() > MAX_JSON_BYTES {
                return Err(ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "JSON 文件过大",
                ));
            }
            let parsed: Value = serde_json::from_str(&content)
                .map_err(|_| ApiError::bad("JSON 格式不正确"))?;
            if !parsed.is_object() && !parsed.is_array() {
                return Err(ApiError::bad("JSON 顶层必须是对象或数组"));
            }
            let entry = loaded
                .entries
                .iter_mut()
                .find(|entry| entry.name == path)
                .ok_or_else(|| ApiError::not_found("主题包里没有这个文件"))?;
            entry.data = content.into_bytes();
            (path, "json")
        }
    };
    let plain = build_zip(&loaded.entries)?;
    let encrypted = encrypt_package(&plain)?;
    // Re-validate the full package instead of only trusting the edited file:
    // theme.json can reference entries by name, so a replacement must not turn
    // a previously valid package into one the manager refuses.
    let info: PackageInfo = crate::package::validate_package(&encrypted)
        .map_err(|error| ApiError::bad(format!("主题包校验失败：{error}")))?;
    let sha256 = sha256_hex(&encrypted);
    let size = encrypted.len() as u64;
    match loaded.info {
        TargetInfo::Theme {
            meta_path,
            mut meta,
        } => {
            state
                .store
                .put_same_location(&meta.package, &encrypted, "application/octet-stream")
                .await
                .map_err(ApiError::internal)?;
            meta.sha256 = Some(sha256.clone());
            meta.asset_size = Some(size);
            meta.updated_at = now_iso();
            meta.format_version = info.package_version;
            if let Err(error) = catalog::write_meta(&meta_path, &meta) {
                // Keep the published package consistent with its metadata.
                let _ = state
                    .store
                    .put_same_location(&meta.package, &loaded.raw, "application/octet-stream")
                    .await;
                return Err(ApiError::internal(error));
            }
            catalog::rebuild_catalog(&state.store, &state.paths)
                .await
                .map_err(ApiError::internal)?;
        }
        TargetInfo::Pending {
            directory,
            mut meta,
        } => {
            let package_path = pending_package_path(&directory, &meta.package)?;
            crate::config::write_atomic_async(&package_path, &encrypted, 0o644)
                .await
                .map_err(ApiError::internal)?;
            meta.sha256 = sha256.clone();
            meta.format_version = info.package_version;
            meta.validation = info.to_json();
            let mut meta_json =
                serde_json::to_vec_pretty(&meta).map_err(ApiError::internal)?;
            meta_json.push(b'\n');
            crate::config::write_atomic_async(&directory.join("meta.json"), &meta_json, 0o644)
                .await
                .map_err(ApiError::internal)?;
        }
    }
    if let Err(error) = accounts::audit(
        &state.db,
        Some(&actor.user_id),
        &format!("theme.files.{action}"),
        Some(kind.label()),
        Some(&loaded.id),
        Some(&format!("{path} · {size} bytes · sha256 {sha256}")),
    )
    .await
    {
        tracing::warn!(?error, "failed to record theme file edit");
    }
    Ok(Json(json!({
        "ok": true,
        "sha256": sha256,
        "size": size,
        "formatVersion": info.package_version,
    })))
}


fn lock_key(state: &AppState, kind: TargetKind, id: &str) -> ApiResult<String> {
    match kind {
        TargetKind::Theme => catalog::find_theme_meta(&state.paths, id)
            .map(|(_, meta)| meta.id)
            .ok_or_else(|| ApiError::not_found("主题不存在")),
        TargetKind::Pending => {
            let Some(directory) = catalog::pending_dir(&state.paths, id) else {
                return Err(ApiError::not_found("待审核主题不存在"));
            };
            let Some(meta) = catalog::pending_meta(&state.paths, &directory) else {
                return Err(ApiError::not_found("待审核主题信息损坏"));
            };
            if meta.id.trim().is_empty() {
                Ok(format!("pending:{id}"))
            } else {
                Ok(meta.id)
            }
        }
    }
}

async fn load_target(state: &AppState, kind: TargetKind, id: &str) -> ApiResult<Loaded> {
    match kind {
        TargetKind::Theme => {
            let Some((meta_path, meta)) = catalog::find_theme_meta(&state.paths, id) else {
                return Err(ApiError::not_found("主题不存在"));
            };
            let raw = state
                .store
                .read(&meta.package)
                .await
                .map_err(|_| ApiError::not_found("主题包读取失败"))?;
            let (plain, entries) = open_package(&raw)?;
            let sha256 = sha256_hex(&raw);
            Ok(Loaded {
                id: meta.id.clone(),
                name: meta.name.clone(),
                version: meta.version,
                sha256,
                size: raw.len() as u64,
                raw,
                plain,
                entries,
                info: TargetInfo::Theme { meta_path, meta },
            })
        }
        TargetKind::Pending => {
            let Some(directory) = catalog::pending_dir(&state.paths, id) else {
                return Err(ApiError::not_found("待审核主题不存在"));
            };
            if !directory.is_dir() {
                return Err(ApiError::not_found("待审核主题不存在"));
            }
            let Some(meta) = catalog::pending_meta(&state.paths, &directory) else {
                return Err(ApiError::not_found("待审核主题信息损坏"));
            };
            let package_path = pending_package_path(&directory, &meta.package)?;
            let raw = tokio::fs::read(&package_path)
                .await
                .map_err(|_| ApiError::not_found("待审核主题包读取失败"))?;
            let (plain, entries) = open_package(&raw)?;
            let sha256 = sha256_hex(&raw);
            Ok(Loaded {
                id: meta.id.clone(),
                name: meta.name.clone(),
                version: meta.version,
                sha256,
                size: raw.len() as u64,
                raw,
                plain,
                entries,
                info: TargetInfo::Pending { directory, meta },
            })
        }
    }
}

fn pending_package_path(directory: &StdPath, package: &str) -> ApiResult<PathBuf> {
    let relative = StdPath::new(package);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ApiError::bad("待审核主题包路径无效"));
    }
    Ok(directory.join(relative))
}

fn open_package(data: &[u8]) -> ApiResult<(Vec<u8>, Vec<Entry>)> {
    let plain = decrypt_package(data)?;
    let entries = read_zip(&plain)?;
    Ok((plain, entries))
}

fn decrypt_package(data: &[u8]) -> ApiResult<Vec<u8>> {
    if data.len() < PACKAGE_MAGIC.len() + 12 + 16 || !data.starts_with(PACKAGE_MAGIC) {
        return Err(ApiError::bad("不是有效的加密主题包"));
    }
    let cipher = Aes256Gcm::new_from_slice(&PACKAGE_KEY)
        .map_err(|_| ApiError::internal("主题包密钥无效"))?;
    let nonce = Nonce::from_slice(&data[PACKAGE_MAGIC.len()..PACKAGE_MAGIC.len() + 12]);
    cipher
        .decrypt(nonce, &data[PACKAGE_MAGIC.len() + 12..])
        .map_err(|_| ApiError::bad("主题包解密失败，文件可能已损坏"))
}

fn encrypt_package(plain: &[u8]) -> ApiResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(&PACKAGE_KEY)
        .map_err(|_| ApiError::internal("主题包密钥无效"))?;
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| ApiError::internal("主题包加密失败"))?;
    let mut output = Vec::with_capacity(PACKAGE_MAGIC.len() + 12 + ciphertext.len());
    output.extend_from_slice(PACKAGE_MAGIC);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn read_zip(plain: &[u8]) -> ApiResult<Vec<Entry>> {
    let mut archive =
        ZipArchive::new(Cursor::new(plain)).map_err(|_| ApiError::bad("主题包不是有效的 ZIP"))?;
    if archive.len() > MAX_ENTRIES {
        return Err(ApiError::bad("主题包条目过多"));
    }
    let mut entries: Vec<Entry> = Vec::new();
    let mut total: u64 = 0;
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|_| ApiError::bad("读取主题包条目失败"))?;
        if file.name().ends_with('/') {
            continue;
        }
        let name = file.name().to_string();
        if name.is_empty() || name.contains('\0') {
            return Err(ApiError::bad("主题包条目名无效"));
        }
        // Zip-slip guard: the decrypted ZIP is offered for download, so never
        // forward absolute paths, parent traversals or Windows separators.
        if name.starts_with('/')
            || name.contains('\\')
            || name.split('/').any(|part| part == "..")
        {
            return Err(ApiError::bad("主题包条目路径不安全"));
        }
        if entries.iter().any(|entry| entry.name == name) {
            return Err(ApiError::bad("主题包条目名重复"));
        }
        let size = file.size();
        if size > MAX_FILE_BYTES {
            return Err(ApiError::bad("主题包内单个文件过大"));
        }
        total = total.saturating_add(size);
        if total > MAX_TOTAL_UNCOMPRESSED {
            return Err(ApiError::bad("主题包解压后过大"));
        }
        let mut data = Vec::with_capacity(size as usize);
        file.read_to_end(&mut data)
            .map_err(|_| ApiError::bad("读取主题包文件失败"))?;
        entries.push(Entry { name, data });
    }
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(entries)
}

fn build_zip(entries: &[Entry]) -> ApiResult<Vec<u8>> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    for entry in entries {
        writer
            .start_file(entry.name.as_str(), options)
            .map_err(|_| ApiError::internal("写入主题包失败"))?;
        writer
            .write_all(&entry.data)
            .map_err(|_| ApiError::internal("写入主题包失败"))?;
    }
    let cursor = writer
        .finish()
        .map_err(|_| ApiError::internal("打包主题包失败"))?;
    Ok(cursor.into_inner())
}

fn safe_filename(value: &str) -> String {
    let cleaned: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "theme-package".to_string()
    } else {
        cleaned
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_and_zip_roundtrip_preserves_entries() {
        let entries = vec![
            Entry {
                name: "theme.json".to_string(),
                data: b"{\"name\":\"demo\"}".to_vec(),
            },
            Entry {
                name: "images/cover.png".to_string(),
                data: vec![1, 2, 3, 4],
            },
        ];
        let plain = build_zip(&entries).expect("zip");
        let encrypted = encrypt_package(&plain).expect("encrypt");
        assert!(encrypted.starts_with(PACKAGE_MAGIC));
        let decrypted = decrypt_package(&encrypted).expect("decrypt");
        let read = read_zip(&decrypted).expect("read zip");
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].name, "images/cover.png");
        assert_eq!(read[0].data, vec![1, 2, 3, 4]);
        assert_eq!(read[1].name, "theme.json");
    }

    #[test]
    fn zip_slip_names_are_rejected() {
        let plain = build_zip(&[Entry {
            name: "../escape.txt".to_string(),
            data: b"x".to_vec(),
        }])
        .expect("zip");
        assert!(read_zip(&plain).is_err());
    }

    #[test]
    fn extensionless_images_are_detected_by_magic() {
        let png = b"\x89PNG\r\n\x1a\nrest";
        let jpeg = b"\xff\xd8\xffrest";
        let webp = b"RIFF\x00\x00\x00\x00WEBPrest";
        assert_eq!(image_mime(png), Some("image/png"));
        assert_eq!(image_mime(jpeg), Some("image/jpeg"));
        assert_eq!(image_mime(webp), Some("image/webp"));
        // Theme packages commonly store previews under names without suffixes.
        assert_eq!(entry_kind("background_dark", png), "image");
        assert_eq!(entry_kind("theme.json", b"{}"), "json");
        assert_eq!(entry_kind("readme", b"hello"), "binary");
        assert_eq!(read_content_type("background_dark", png), "image/png");
    }

    #[test]
    fn safe_filename_keeps_ids_but_strips_paths() {
        assert_eq!(safe_filename("demo-theme"), "demo-theme");
        assert_eq!(safe_filename("../../etc/passwd"), ".._.._etc_passwd");
    }
}
