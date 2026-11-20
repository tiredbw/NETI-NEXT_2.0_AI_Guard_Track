//! Раздача фронтенда со своего origin и CORS для отдельного dev-сервера фронта.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use crate::app::AppState;

/// Тип содержимого по расширению; только то, что есть во frontend/.
fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()).unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "ico" => "image/x-icon",
        "md" | "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

/// Безопасно превращает путь URL в путь внутри каталога фронта: без «..», абсолютных путей и скрытых файлов.
pub fn resolve(root: &Path, url_path: &str) -> Option<PathBuf> {
    let rel = url_path.trim_start_matches('/');
    let rel = if rel.is_empty() { "index.html" } else { rel };
    if rel.contains('\\') || rel.contains('\0') { return None; }
    let mut out = root.to_path_buf();
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(part) => {
                if part.to_str().is_none_or(|s| s.starts_with('.')) { return None; }
                out.push(part);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// GET вне /v1: файлы из FRONTEND_DIR. Без каталога — 404.
pub async fn static_files(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let Some(root) = state.frontend_dir.as_ref() else { return StatusCode::NOT_FOUND.into_response() };
    if req.method() != Method::GET && req.method() != Method::HEAD { return StatusCode::METHOD_NOT_ALLOWED.into_response(); }
    if req.uri().path().starts_with("/v1/") { return crate::app::error(StatusCode::NOT_FOUND, "not_found", "Маршрут не найден"); }
    let Some(path) = resolve(root, req.uri().path()) else { return StatusCode::NOT_FOUND.into_response() };
    match tokio::fs::read(&path).await {
        Ok(bytes) => {
            // ETag по содержимому: браузер перепроверяет файл на каждой загрузке и получает новую версию сразу после обновления.
            let tag = etag(&bytes);
            let fresh = req.headers().get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|t| t.trim() == tag));
            let builder = Response::builder()
                .header(header::ETAG, &tag)
                .header(header::CACHE_CONTROL, "no-cache")
                .header("x-content-type-options", "nosniff");
            let resp = if fresh {
                builder.status(StatusCode::NOT_MODIFIED).body(Body::empty())
            } else {
                builder.header(header::CONTENT_TYPE, content_type(&path)).body(Body::from(bytes))
            };
            resp.unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Сильный ETag: первые 16 байт sha256 содержимого в hex и в кавычках.
pub fn etag(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("\"{}\"", hex::encode(&Sha256::digest(bytes)[..16]))
}

/// CORS только для перечисленных origin (CORS_ORIGINS). Свой origin в CORS не нуждается.
pub async fn cors(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Response {
    let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let allowed = origin.filter(|o| state.cors_origins.iter().any(|a| a == o));
    if req.method() == Method::OPTIONS {
        let mut resp = StatusCode::NO_CONTENT.into_response();
        if let Some(o) = &allowed { add_cors(&mut resp, o); }
        return resp;
    }
    let mut resp = next.run(req).await;
    if let Some(o) = &allowed { add_cors(&mut resp, o); }
    resp
}

fn add_cors(resp: &mut Response, origin: &str) {
    let h = resp.headers_mut();
    if let Ok(v) = HeaderValue::from_str(origin) { h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v); }
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Content-Type, X-Admin-Token, X-Guard-Client"));
    h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
}

#[cfg(test)]
mod tests {
    use super::resolve;
    use std::path::Path;

    #[test]
    fn etag_follows_content() {
        let a = super::etag(b"one");
        assert_eq!(a, super::etag(b"one"));
        assert_ne!(a, super::etag(b"two"));
        assert!(a.starts_with('"') && a.ends_with('"') && a.len() == 34);
    }

    #[test]
    fn blocks_traversal() {
        let root = Path::new("/srv/front");
        assert_eq!(resolve(root, "/").unwrap(), Path::new("/srv/front/index.html"));
        assert_eq!(resolve(root, "/js/app.js").unwrap(), Path::new("/srv/front/js/app.js"));
        assert!(resolve(root, "/../secret").is_none());
        assert!(resolve(root, "/js/../../etc/passwd").is_none());
        assert!(resolve(root, "/.env").is_none());
        assert!(resolve(root, "/a\\b").is_none());
    }
}
