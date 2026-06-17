use std::net::SocketAddr;

use anyhow::Result;
use axum::{
    body::Body,
    extract::Multipart,
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
use tower_http::cors::CorsLayer;

const INDEX_HTML: &str = include_str!("../static/index.html");
const STYLE_CSS: &str = include_str!("../static/styles.css");
const APP_JS: &str = include_str!("../static/app.js");

pub async fn run(addr: SocketAddr) -> Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/styles.css", get(styles))
        .route("/app.js", get(script))
        .route("/api/prepare-tune", post(prepare_tune_handler))
        .route("/api/prepare-program", post(prepare_program_handler))
        .route("/api/validate", post(validate_handler))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("MS45 web UI listening at http://{}", listener.local_addr()?);
    axum::serve(listener, app).await?;
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

async fn prepare_tune_handler(multipart: Multipart) -> Response {
    match read_multipart(multipart).await.and_then(|parts| {
        let input = parts.file("input")?;
        Ok(prepare_tune(input)?.data)
    }) {
        Ok(bytes) => download("tune.prepared.bin", bytes),
        Err(err) => api_error(StatusCode::BAD_REQUEST, err),
    }
}

async fn prepare_program_handler(multipart: Multipart) -> Response {
    match read_multipart(multipart).await.and_then(|parts| {
        let external = parts.file("external")?;
        let mpc = parts.file("mpc")?;
        let payload = prepare_full_program(external, mpc)?;
        Ok(payload)
    }) {
        Ok(payload) => {
            let zip = zip_store(&[
                ("external_program.prepared.bin", &payload.external_program),
                ("mpc_program.prepared.bin", &payload.mpc_program),
            ]);
            download("ms45-program-payload.zip", zip)
        }
        Err(err) => api_error(StatusCode::BAD_REQUEST, err),
    }
}

async fn validate_handler(multipart: Multipart) -> Response {
    match read_multipart(multipart).await.and_then(|parts| {
        let mut checks = Vec::new();

        if let Some(tune) = parts.optional_file("tune") {
            if let Some(sw_ref) = parts.optional_text("sw_ref") {
                if !sw_ref.trim().is_empty() {
                    checks.push(json!({
                        "name": "tune/software reference",
                        "ok": verify_parameter_match(tune, sw_ref.trim())?
                    }));
                }
            }
        }

        if let Some(external) = parts.optional_file("external") {
            if let Some(hw_ref) = parts.optional_text("hw_ref") {
                if !hw_ref.trim().is_empty() {
                    checks.push(json!({
                        "name": "program/hardware reference",
                        "ok": verify_program_match(external, hw_ref.trim())?
                    }));
                }
            }
            if let Some(mpc) = parts.optional_file("mpc") {
                checks.push(json!({
                    "name": "external/MPC pair",
                    "ok": verify_flash_mpc_match(external, mpc)?
                }));
            }
        }

        if checks.is_empty() {
            anyhow::bail!("provide at least one file/reference validation input");
        }
        Ok(checks)
    }) {
        Ok(checks) => Json(json!({ "checks": checks })).into_response(),
        Err(err) => api_error(StatusCode::BAD_REQUEST, err),
    }
}

#[derive(Default)]
struct Parts {
    fields: Vec<(String, Vec<u8>)>,
}

impl Parts {
    fn file(&self, name: &str) -> anyhow::Result<&[u8]> {
        self.optional_file(name)
            .ok_or_else(|| anyhow::anyhow!("missing file field '{name}'"))
    }

    fn optional_file(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(field, value)| field == name && !value.is_empty())
            .map(|(_, value)| value.as_slice())
    }

    fn optional_text(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
    }
}

async fn read_multipart(mut multipart: Multipart) -> anyhow::Result<Parts> {
    let mut parts = Parts::default();
    while let Some(field) = multipart.next_field().await? {
        let Some(name) = field.name().map(str::to_string) else {
            continue;
        };
        let bytes = field.bytes().await?.to_vec();
        parts.fields.push((name, bytes));
    }
    Ok(parts)
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
