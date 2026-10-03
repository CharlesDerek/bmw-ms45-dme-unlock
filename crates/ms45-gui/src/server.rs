use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Result;
use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Multipart, State},
    http::{header, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use ms45_core::{
    prepare_full_program, prepare_tune, verify_flash_mpc_match, verify_parameter_match,
    verify_program_match,
};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

const INDEX_HTML: &str = include_str!("../static/index.html");
const STYLE_CSS: &str = include_str!("../static/styles.css");
const APP_JS: &str = include_str!("../static/app.js");
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_UPLOAD_BYTES: usize = 2 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct AppState {
    upload_root: PathBuf,
}

pub async fn run(addr: SocketAddr, allow_non_loopback: bool) -> Result<()> {
    validate_bind_address(addr, allow_non_loopback)?;
    let upload_root = tempfile::Builder::new().prefix("ms45-web-").tempdir()?;
    let app = app(
        AppState {
            upload_root: upload_root.path().to_owned(),
        },
        REQUEST_TIMEOUT,
    );

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("MS45 web UI listening at http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

fn app(state: AppState, request_timeout: Duration) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(script))
        .route("/api/prepare-tune", post(prepare_tune_handler))
        .route("/api/prepare-program", post(prepare_program_handler))
        .route("/api/validate", post(validate_handler))
        .route("/api/inspect-flash-plan", post(inspect_flash_plan_handler))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ))
        .with_state(state)
}

fn validate_bind_address(addr: SocketAddr, allow_non_loopback: bool) -> Result<()> {
    if !addr.ip().is_loopback() && !allow_non_loopback {
        anyhow::bail!(
            "refusing to listen on non-loopback address {}; pass --allow-non-loopback to acknowledge network exposure",
            addr.ip()
        );
    }
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn styles() -> impl IntoResponse {
    ([("content-type", "text/css; charset=utf-8")], STYLE_CSS)
}

async fn script() -> impl IntoResponse {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn prepare_tune_handler(State(state): State<AppState>, multipart: Multipart) -> Response {
    match read_multipart(multipart, &state.upload_root)
        .await
        .and_then(|parts| {
            let input = parts.file("input")?;
            Ok(prepare_tune(&input)?.data)
        }) {
        Ok(bytes) => download("tune.prepared.bin", bytes),
        Err(err) => request_error(err),
    }
}

async fn prepare_program_handler(State(state): State<AppState>, multipart: Multipart) -> Response {
    match read_multipart(multipart, &state.upload_root)
        .await
        .and_then(|parts| {
            let external = parts.file("external")?;
            let mpc = parts.file("mpc")?;
            let payload = prepare_full_program(&external, &mpc)?;
            Ok(payload)
        }) {
        Ok(payload) => {
            let zip = zip_store(&[
                ("external_program.prepared.bin", &payload.external_program),
                ("mpc_program.prepared.bin", &payload.mpc_program),
            ]);
            download("ms45-program-payload.zip", zip)
        }
        Err(err) => request_error(err),
    }
}

async fn validate_handler(State(state): State<AppState>, multipart: Multipart) -> Response {
    match read_multipart(multipart, &state.upload_root)
        .await
        .and_then(|parts| {
            let mut checks = Vec::new();

            if let Some(tune) = parts.optional_file("tune") {
                if let Some(sw_ref) = parts.optional_text("sw_ref") {
                    if !sw_ref.trim().is_empty() {
                        checks.push(json!({
                            "name": "tune/software reference",
                            "ok": verify_parameter_match(&tune, sw_ref.trim())?
                        }));
                    }
                }
            }

            if let Some(external) = parts.optional_file("external") {
                if let Some(hw_ref) = parts.optional_text("hw_ref") {
                    if !hw_ref.trim().is_empty() {
                        checks.push(json!({
                            "name": "program/hardware reference",
                            "ok": verify_program_match(&external, hw_ref.trim())?
                        }));
                    }
                }
                if let Some(mpc) = parts.optional_file("mpc") {
                    checks.push(json!({
                        "name": "external/MPC pair",
                        "ok": verify_flash_mpc_match(&external, &mpc)?
                    }));
                }
            }

            if checks.is_empty() {
                anyhow::bail!("provide at least one file/reference validation input");
            }
            Ok(checks)
        }) {
        Ok(checks) => Json(json!({ "checks": checks })).into_response(),
        Err(err) => request_error(err),
    }
}

async fn inspect_flash_plan_handler(
    State(state): State<AppState>,
    multipart: Multipart,
) -> Response {
    match read_multipart(multipart, &state.upload_root)
        .await
        .and_then(|parts| {
            let plan = parts.file("plan")?;
            let artifact = ms45::flash_plan_artifact::read_and_verify_bytes(
                &plan,
                parts
                    .optional_text("expected_public_key")
                    .ok_or_else(|| anyhow::anyhow!("missing expected public key"))?
                    .trim(),
            )?;
            serde_json::to_value(ms45::flash_plan_artifact::inspect(&artifact)).map_err(Into::into)
        }) {
        Ok(inspection) => Json(inspection).into_response(),
        Err(err) => request_error(err),
    }
}

struct Parts {
    _directory: tempfile::TempDir,
    fields: Vec<(String, PathBuf)>,
}

impl Parts {
    fn file(&self, name: &str) -> anyhow::Result<Vec<u8>> {
        self.optional_file(name)
            .ok_or_else(|| anyhow::anyhow!("missing file field '{name}'"))
    }

    fn optional_file(&self, name: &str) -> Option<Vec<u8>> {
        self.fields
            .iter()
            .find(|(field, path)| {
                field == name && path.metadata().is_ok_and(|metadata| metadata.len() > 0)
            })
            .and_then(|(_, path)| std::fs::read(path).ok())
    }

    fn optional_text(&self, name: &str) -> Option<String> {
        self.optional_file(name)
            .and_then(|value| String::from_utf8(value).ok())
    }
}

#[derive(Debug)]
struct UploadTooLarge;

impl std::fmt::Display for UploadTooLarge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("upload exceeds the configured size limit")
    }
}

impl std::error::Error for UploadTooLarge {}

async fn read_multipart(mut multipart: Multipart, upload_root: &Path) -> anyhow::Result<Parts> {
    let directory = tempfile::Builder::new()
        .prefix("request-")
        .tempdir_in(upload_root)?;
    let mut fields = Vec::new();
    let mut total_bytes = 0usize;
    while let Some(mut field) = multipart.next_field().await? {
        let Some(name) = field.name().map(str::to_string) else {
            continue;
        };
        let path = directory.path().join(fields.len().to_string());
        let mut output = tokio::fs::File::create(&path).await?;
        let mut field_bytes = 0usize;
        while let Some(chunk) = field.chunk().await? {
            field_bytes = field_bytes.checked_add(chunk.len()).ok_or(UploadTooLarge)?;
            total_bytes = total_bytes.checked_add(chunk.len()).ok_or(UploadTooLarge)?;
            if field_bytes > MAX_FIELD_BYTES || total_bytes > MAX_UPLOAD_BYTES {
                return Err(UploadTooLarge.into());
            }
            output.write_all(&chunk).await?;
        }
        output.flush().await?;
        fields.push((name, path));
    }
    Ok(Parts {
        _directory: directory,
        fields,
    })
}

fn download(name: &str, bytes: Vec<u8>) -> Response {
    let mut response = Body::from(bytes).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{name}\""))
            .expect("static filename header is valid"),
    );
    response
}

fn zip_store(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();

    for (name, data) in files {
        let name_bytes = name.as_bytes();
        let offset = out.len() as u32;
        let crc = crc32fast::hash(data);

        write_u32(&mut out, 0x0403_4b50);
        write_u16(&mut out, 20);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u16(&mut out, 0);
        write_u32(&mut out, crc);
        write_u32(&mut out, data.len() as u32);
        write_u32(&mut out, data.len() as u32);
        write_u16(&mut out, name_bytes.len() as u16);
        write_u16(&mut out, 0);
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        write_u32(&mut central, 0x0201_4b50);
        write_u16(&mut central, 20);
        write_u16(&mut central, 20);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u32(&mut central, crc);
        write_u32(&mut central, data.len() as u32);
        write_u32(&mut central, data.len() as u32);
        write_u16(&mut central, name_bytes.len() as u16);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u16(&mut central, 0);
        write_u32(&mut central, 0);
        write_u32(&mut central, offset);
        central.extend_from_slice(name_bytes);
    }

    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    write_u32(&mut out, 0x0605_4b50);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, files.len() as u16);
    write_u16(&mut out, files.len() as u16);
    write_u32(&mut out, central.len() as u32);
    write_u32(&mut out, central_offset);
    write_u16(&mut out, 0);
    out
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn api_error(status: StatusCode, err: anyhow::Error) -> Response {
    (status, Json(json!({ "error": err.to_string() }))).into_response()
}

fn request_error(err: anyhow::Error) -> Response {
    let status = if err.is::<UploadTooLarge>() {
        StatusCode::PAYLOAD_TOO_LARGE
    } else {
        StatusCode::BAD_REQUEST
    };
    api_error(status, err)
}

#[cfg(test)]
mod tests {
    use std::{convert::Infallible, net::IpAddr};

    use axum::{
        body::{Body, Bytes},
        http::{header, Method, Request},
    };
    use tower::ServiceExt;

    use super::*;

    fn test_app(root: &Path, timeout: Duration) -> Router {
        app(
            AppState {
                upload_root: root.to_owned(),
            },
            timeout,
        )
    }

    fn multipart(field_name: &str, value: &[u8]) -> (String, Vec<u8>) {
        let boundary = "ms45-test-boundary";
        let mut body = format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{field_name}\"; filename=\"input.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
        )
        .into_bytes();
        body.extend_from_slice(value);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        (format!("multipart/form-data; boundary={boundary}"), body)
    }

    fn assert_upload_root_empty(root: &Path) {
        assert_eq!(std::fs::read_dir(root).unwrap().count(), 0);
    }

    #[test]
    fn requires_explicit_opt_in_for_non_loopback_bind() {
        let remote = SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 4580);
        let loopback = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 4580);

        assert!(validate_bind_address(remote, false).is_err());
        assert!(validate_bind_address(remote, true).is_ok());
        assert!(validate_bind_address(loopback, false).is_ok());
    }

    #[tokio::test]
    async fn rejects_request_bodies_over_the_server_limit() {
        let root = tempfile::tempdir().unwrap();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/prepare-tune")
            .header(
                header::CONTENT_TYPE,
                "multipart/form-data; boundary=ms45-test-boundary",
            )
            .header(header::CONTENT_LENGTH, MAX_REQUEST_BODY_BYTES + 1)
            .body(Body::from(vec![0; MAX_REQUEST_BODY_BYTES + 1]))
            .unwrap();

        let response = test_app(root.path(), REQUEST_TIMEOUT)
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_upload_root_empty(root.path());
    }

    #[tokio::test]
    async fn rejects_oversized_fields_and_cleans_temporary_files() {
        let root = tempfile::tempdir().unwrap();
        let (content_type, body) = multipart("input", &vec![0; MAX_FIELD_BYTES + 1]);
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/prepare-tune")
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(body))
            .unwrap();

        let response = test_app(root.path(), REQUEST_TIMEOUT)
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_upload_root_empty(root.path());
    }

    #[tokio::test]
    async fn timeout_cancels_upload_and_cleans_temporary_files() {
        let root = tempfile::tempdir().unwrap();
        let stream = futures_util::stream::pending::<Result<Bytes, Infallible>>();
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/prepare-tune")
            .header(
                header::CONTENT_TYPE,
                "multipart/form-data; boundary=ms45-test-boundary",
            )
            .body(Body::from_stream(stream))
            .unwrap();

        let response = test_app(root.path(), Duration::from_millis(10))
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        assert_upload_root_empty(root.path());
    }

    #[tokio::test]
    async fn does_not_allow_cross_origin_requests() {
        let root = tempfile::tempdir().unwrap();
        let request = Request::builder()
            .method(Method::OPTIONS)
            .uri("/api/prepare-tune")
            .header(header::ORIGIN, "https://example.invalid")
            .body(Body::empty())
            .unwrap();

        let response = test_app(root.path(), REQUEST_TIMEOUT)
            .oneshot(request)
            .await
            .unwrap();

        assert!(response
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none());
    }
}
