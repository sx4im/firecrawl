//! Plain HTTP fetch: one shared connection pool, guarded DNS, guarded
//! redirects, a body size cap and charset-aware decoding.

use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};

use bytes::BytesMut;
use futures::StreamExt;
use reqwest::{
  dns::{Addrs, Name, Resolve, Resolving},
  header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE},
  redirect, Client,
};
use url::Url;

use crate::guard::{self, Blocked, NetworkPolicy};

/// Looks like a browser to naive checks, and names itself so a site owner can
/// find and block it.
pub const USER_AGENT: &str = concat!(
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 ",
  "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 ",
  "FirecrawlLocal/",
  env!("CARGO_PKG_VERSION"),
  " (+https://firecrawl.dev/local)"
);

pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
const MAX_REDIRECTS: usize = 10;

/// The default `Accept` header.
const DEFAULT_ACCEPT: &str =
  "text/html,application/xhtml+xml,application/xml;q=0.9,text/markdown;q=0.9,*/*;q=0.8";

/// The default `Accept` header without the `text/markdown` entry.
const ACCEPT_WITHOUT_MARKDOWN: &str =
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

#[derive(Debug)]
pub enum FetchError {
  Blocked(String),
  Timeout,
  TooLarge,
  Network(String),
}

impl std::fmt::Display for FetchError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      FetchError::Blocked(m) => write!(f, "blocked: {m}"),
      FetchError::Timeout => write!(f, "the request timed out"),
      FetchError::TooLarge => write!(f, "the response is larger than {MAX_BODY_BYTES} bytes"),
      FetchError::Network(m) => write!(f, "network error: {m}"),
    }
  }
}

impl std::error::Error for FetchError {}

pub struct FetchResult {
  pub status: u16,
  pub final_url: Url,
  pub content_type: Option<String>,
  pub body: bytes::Bytes,
  pub headers: HeaderMap,
}

impl FetchResult {
  /// Media type without parameters, lowercased.
  pub fn mime(&self) -> Option<String> {
    self.content_type.as_deref().map(|ct| {
      ct.split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
    })
  }

  /// Decode the body to text: charset from the header, then a `<meta>` sniff,
  /// then UTF-8.
  pub fn text(&self) -> String {
    decode_body(&self.body, self.content_type.as_deref())
  }
}

fn charset_from_content_type(ct: &str) -> Option<&str> {
  ct.split(';').skip(1).find_map(|part| {
    let (k, v) = part.split_once('=')?;
    if k.trim().eq_ignore_ascii_case("charset") {
      Some(v.trim().trim_matches('"').trim_matches('\''))
    } else {
      None
    }
  })
}

fn sniff_meta_charset(body: &[u8]) -> Option<String> {
  let head = &body[..body.len().min(4096)];
  let lower = String::from_utf8_lossy(head).to_ascii_lowercase();
  let idx = lower.find("charset=")?;
  let rest = &lower[idx + 8..];
  let rest = rest.trim_start_matches(['"', '\'', ' ']);
  let end = rest
    .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
    .unwrap_or(rest.len());
  if end == 0 {
    None
  } else {
    Some(rest[..end].to_string())
  }
}

pub fn decode_body(body: &[u8], content_type: Option<&str>) -> String {
  let label = content_type
    .and_then(charset_from_content_type)
    .map(str::to_string)
    .or_else(|| sniff_meta_charset(body));
  if let Some(label) = label {
    if let Some(enc) = encoding_rs::Encoding::for_label(label.as_bytes()) {
      if enc != encoding_rs::UTF_8 {
        let (text, _, _) = enc.decode(body);
        return text.into_owned();
      }
    }
  }
  match std::str::from_utf8(body) {
    Ok(s) => s.to_owned(),
    Err(_) => String::from_utf8_lossy(body).into_owned(),
  }
}

/// DNS resolver that drops every address the policy forbids. A hostname that
/// only resolves to forbidden addresses fails to connect.
struct GuardedResolver {
  policy: NetworkPolicy,
}

impl Resolve for GuardedResolver {
  fn resolve(&self, name: Name) -> Resolving {
    let policy = self.policy;
    Box::pin(async move {
      let host = name.as_str().to_string();
      let resolved: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0)).await?.collect();
      let allowed: Vec<SocketAddr> = resolved
        .into_iter()
        .filter(|a| guard::check_ip(a.ip(), policy).is_ok())
        .collect();
      if allowed.is_empty() {
        let err: Box<dyn std::error::Error + Send + Sync> = Box::new(Blocked(format!(
          "{host} does not resolve to an address Firecrawl Local may reach"
        )));
        return Err(err);
      }
      let addrs: Addrs = Box::new(allowed.into_iter());
      Ok(addrs)
    })
  }
}

#[derive(Clone)]
pub struct Fetcher {
  client: Client,
  policy: NetworkPolicy,
}

#[derive(Default, Clone)]
pub struct FetchOptions {
  pub headers: HashMap<String, String>,
  pub timeout: Option<Duration>,
}

impl Fetcher {
  pub fn new(policy: NetworkPolicy, user_agent: Option<&str>) -> Result<Self, String> {
    let mut default_headers = HeaderMap::new();
    default_headers.insert(ACCEPT, HeaderValue::from_static(DEFAULT_ACCEPT));
    default_headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));

    let redirect_policy = redirect::Policy::custom(move |attempt| {
      if attempt.previous().len() >= MAX_REDIRECTS {
        return attempt.error(Blocked(format!("more than {MAX_REDIRECTS} redirects")));
      }
      match guard::check_url(attempt.url(), policy) {
        Ok(()) => attempt.follow(),
        Err(e) => attempt.error(e),
      }
    });

    let client = Client::builder()
      .user_agent(user_agent.unwrap_or(USER_AGENT))
      .default_headers(default_headers)
      .redirect(redirect_policy)
      .dns_resolver(Arc::new(GuardedResolver { policy }))
      .connect_timeout(Duration::from_secs(10))
      .pool_idle_timeout(Duration::from_secs(60))
      .pool_max_idle_per_host(64)
      .tcp_nodelay(true)
      .build()
      .map_err(|e| format!("could not build HTTP client: {e}"))?;

    Ok(Self { client, policy })
  }

  pub fn policy(&self) -> NetworkPolicy {
    self.policy
  }

  /// Fetch a URL, retrying once when the connection itself failed (a reset,
  /// a DNS hiccup, a dropped handshake). Those are usually gone a moment
  /// later; a refused certificate, a timeout or a guard refusal is not.
  ///
  /// A 4xx answer is also retried once without `text/markdown` in `Accept`
  /// when the request advertised it: some hosts route any request that
  /// mentions `text/markdown` to their markdown variant, ignoring q-values,
  /// and answer 404 for pages that exist as HTML (react.dev does this).
  pub async fn fetch(&self, url: &Url, opts: &FetchOptions) -> Result<FetchResult, FetchError> {
    match self.fetch_once(url, opts).await {
      Err(FetchError::Network(msg)) if is_transient(&msg) => {
        tokio::time::sleep(Duration::from_millis(250)).await;
        self.fetch_once(url, opts).await
      }
      Ok(result) if (400..500).contains(&result.status) && advertised_markdown(opts) => {
        let mut retry_opts = opts.clone();
        retry_opts
          .headers
          .retain(|k, _| !k.eq_ignore_ascii_case("accept"));
        retry_opts
          .headers
          .insert(ACCEPT.to_string(), ACCEPT_WITHOUT_MARKDOWN.to_string());
        self.fetch_once(url, &retry_opts).await
      }
      other => other,
    }
  }

  async fn fetch_once(&self, url: &Url, opts: &FetchOptions) -> Result<FetchResult, FetchError> {
    guard::check_url(url, self.policy).map_err(|e| FetchError::Blocked(e.0))?;

    let timeout = opts.timeout.unwrap_or(Duration::from_secs(30));
    let mut req = self.client.get(url.clone()).timeout(timeout);
    for (k, v) in &opts.headers {
      if let (Ok(name), Ok(value)) = (
        HeaderName::from_bytes(k.as_bytes()),
        HeaderValue::from_str(v),
      ) {
        req = req.header(name, value);
      }
    }

    let resp = req.send().await.map_err(classify)?;
    let status = resp.status().as_u16();
    let final_url = resp.url().clone();
    let headers = resp.headers().clone();
    let content_type = headers
      .get(CONTENT_TYPE)
      .and_then(|v| v.to_str().ok())
      .map(str::to_string);

    if let Some(len) = resp.content_length() {
      if len as usize > MAX_BODY_BYTES {
        return Err(FetchError::TooLarge);
      }
    }

    let mut buf = BytesMut::with_capacity(resp.content_length().unwrap_or(64 * 1024) as usize);
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
      let chunk = chunk.map_err(classify)?;
      if buf.len() + chunk.len() > MAX_BODY_BYTES {
        return Err(FetchError::TooLarge);
      }
      buf.extend_from_slice(&chunk);
    }

    Ok(FetchResult {
      status,
      final_url,
      content_type,
      body: buf.freeze(),
      headers,
    })
  }
}

/// Whether the request advertises `text/markdown`: the caller's `Accept`
/// override when it sets one, else the default header.
fn advertised_markdown(opts: &FetchOptions) -> bool {
  opts
    .headers
    .iter()
    .find(|(k, _)| k.eq_ignore_ascii_case("accept"))
    .map(|(_, v)| v.as_str())
    .unwrap_or(DEFAULT_ACCEPT)
    .contains("text/markdown")
}

/// A network failure worth one more try: anything but a certificate the
/// client refuses, which fails the same way every time.
fn is_transient(message: &str) -> bool {
  let lower = message.to_ascii_lowercase();
  !(lower.contains("certificate") || lower.contains("unsupported protocol"))
}

fn classify(e: reqwest::Error) -> FetchError {
  if e.is_timeout() {
    return FetchError::Timeout;
  }
  // The guard's refusals travel inside reqwest errors (redirect policy and
  // DNS resolver); surface them as Blocked instead of a generic failure.
  let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
  while let Some(err) = source {
    if let Some(blocked) = err.downcast_ref::<Blocked>() {
      return FetchError::Blocked(blocked.0.clone());
    }
    source = err.source();
  }
  let mut msg = e.to_string();
  let mut source = std::error::Error::source(&e);
  while let Some(err) = source {
    msg.push_str(": ");
    msg.push_str(&err.to_string());
    source = err.source();
  }
  FetchError::Network(msg)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn charset_header_wins() {
    assert_eq!(
      charset_from_content_type("text/html; charset=ISO-8859-1"),
      Some("ISO-8859-1")
    );
    let body = [b'c', b'a', b'f', 0xe9];
    assert_eq!(
      decode_body(&body, Some("text/html; charset=iso-8859-1")),
      "café"
    );
  }

  #[test]
  fn meta_charset_sniffed() {
    let mut body = b"<html><head><meta charset=\"windows-1252\"></head><body>".to_vec();
    body.push(0x93);
    body.extend_from_slice(b"hi");
    body.push(0x94);
    let text = decode_body(&body, Some("text/html"));
    assert!(text.contains('\u{201c}') && text.contains('\u{201d}'));
  }

  #[test]
  fn utf8_default() {
    assert_eq!(decode_body("héllo".as_bytes(), None), "héllo");
  }

  use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
  };

  /// How the test server answers.
  #[derive(Clone, Copy, PartialEq, Eq)]
  enum ServerMode {
    /// 404 when the request advertises text/markdown, 200 otherwise (react.dev).
    Markdown404,
    /// 404 whatever the request says.
    Always404,
    /// 200 whatever the request says.
    Always200,
  }

  /// A loopback server that counts requests; returns its base URL and the counter.
  async fn start_server(mode: ServerMode) -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&hits);
    let app = axum::Router::new().route(
      "/",
      axum::routing::get(move |headers: axum::http::HeaderMap| async move {
        counted.fetch_add(1, Ordering::SeqCst);
        let advertises_markdown = headers
          .get(axum::http::header::ACCEPT)
          .and_then(|v| v.to_str().ok())
          .is_some_and(|v| v.contains("text/markdown"));
        let status = match mode {
          ServerMode::Always200 => axum::http::StatusCode::OK,
          ServerMode::Always404 => axum::http::StatusCode::NOT_FOUND,
          ServerMode::Markdown404 => {
            if advertises_markdown {
              axum::http::StatusCode::NOT_FOUND
            } else {
              axum::http::StatusCode::OK
            }
          }
        };
        let body = if status.is_success() {
          "hello page"
        } else {
          "Not Found"
        };
        (status, body)
      }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
      axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/"), hits)
  }

  async fn fetch(url: &str, opts: &FetchOptions) -> FetchResult {
    let fetcher = Fetcher::new(NetworkPolicy::AllowPrivate, None).unwrap();
    fetcher
      .fetch(&Url::parse(url).unwrap(), opts)
      .await
      .unwrap()
  }

  #[tokio::test]
  async fn client_error_is_retried_without_markdown() {
    let (base, hits) = start_server(ServerMode::Markdown404).await;
    let res = fetch(&base, &FetchOptions::default()).await;
    assert_eq!(res.status, 200);
    assert_eq!(res.text(), "hello page");
    assert_eq!(hits.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn client_error_without_markdown_still_reports_the_error() {
    let (base, hits) = start_server(ServerMode::Always404).await;
    let res = fetch(&base, &FetchOptions::default()).await;
    assert_eq!(res.status, 404);
    assert_eq!(hits.load(Ordering::SeqCst), 2);
  }

  #[tokio::test]
  async fn success_is_not_retried() {
    let (base, hits) = start_server(ServerMode::Always200).await;
    let res = fetch(&base, &FetchOptions::default()).await;
    assert_eq!(res.status, 200);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
  }

  #[tokio::test]
  async fn custom_accept_without_markdown_is_not_retried() {
    let (base, hits) = start_server(ServerMode::Always404).await;
    let mut opts = FetchOptions::default();
    opts
      .headers
      .insert("accept".to_string(), "text/html,*/*;q=0.8".to_string());
    let res = fetch(&base, &opts).await;
    assert_eq!(res.status, 404);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
  }
}
