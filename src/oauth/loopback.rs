//! The loopback redirect endpoint for an authorization-code login (RFC 8252). It listens on
//! IPv4 loopback only, answers the one callback carrying the expected `state` (ignoring any
//! other), and gives up after a timeout.

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::error::{Error, Result};
use crate::secret::SecretString;

const PAGE_DONE: &str = "<!doctype html><meta charset=utf-8><title>Signed in</title>\
<body style=\"font-family:system-ui,sans-serif;margin:3rem\"><h1>Signed in</h1>\
<p>You can close this tab and return to the terminal.</p>";

const PAGE_FAILED: &str = "<!doctype html><meta charset=utf-8><title>Sign-in failed</title>\
<body style=\"font-family:system-ui,sans-serif;margin:3rem\"><h1>Sign-in failed</h1>\
<p>Return to the terminal for details.</p>";

#[derive(Debug)]
pub struct Loopback {
    listener: TcpListener,
    port: u16,
}

type Outcome = Result<SecretString>;

impl Loopback {
    /// Binds `127.0.0.1` on `port`, or on an ephemeral port when `None`.
    pub async fn bind(port: Option<u16>) -> Result<Self> {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port.unwrap_or(0)));
        let listener = TcpListener::bind(addr).await.map_err(|err| {
            Error::io(
                format!("could not listen on {addr} for the sign-in redirect"),
                err,
            )
        })?;
        let port = listener
            .local_addr()
            .map_err(|err| Error::io("could not read the loopback address", err))?
            .port();
        Ok(Self { listener, port })
    }

    pub fn redirect_uri(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// Waits for the redirect to `path` and returns its authorization code.
    pub async fn wait_for_code(
        self,
        path: &str,
        state: &str,
        timeout: Duration,
    ) -> Result<SecretString> {
        let (tx, mut rx) = mpsc::channel::<Outcome>(1);
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let stream = match accepted {
                        Ok((stream, _)) => stream,
                        Err(err) => {
                            // Persistent errors such as EMFILE would otherwise spin this loop.
                            tracing::debug!("accept failed: {err}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                    };
                    let handler = Handler {
                        path: path.to_owned(),
                        state: state.to_owned(),
                        outcome: Arc::default(),
                    };
                    let tx = tx.clone();
                    // Each connection is served on its own task: a browser may open speculative
                    // connections that never send a request.
                    tokio::spawn(async move {
                        let outcome = Arc::clone(&handler.outcome);
                        let service = service_fn(move |req| {
                            let handler = handler.clone();
                            async move { Ok::<_, Infallible>(handler.handle(&req)) }
                        });
                        let _ = http1::Builder::new()
                            .keep_alive(false)
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                        // Report only after the response is written, so the browser sees it.
                        let taken = outcome.lock().expect("the outcome lock is never poisoned").take();
                        if let Some(outcome) = taken {
                            let _ = tx.send(outcome).await;
                        }
                    });
                }
                Some(outcome) = rx.recv() => return outcome,
                () = &mut deadline => {
                    return Err(Error::login(format!(
                        "no sign-in completed within {} seconds", timeout.as_secs()
                    ))
                    .with_hint("run the login again"));
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Handler {
    path: String,
    state: String,
    outcome: Arc<Mutex<Option<Outcome>>>,
}

impl Handler {
    fn handle(&self, req: &Request<Incoming>) -> Response<Full<Bytes>> {
        if req.method() != Method::GET || req.uri().path() != self.path {
            return page(StatusCode::NOT_FOUND, "Not found");
        }
        let mut code = None;
        let mut state = None;
        let mut error = None;
        let mut description = None;
        for (key, value) in url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
        {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                "error_description" => description = Some(value.into_owned()),
                _ => {}
            }
        }
        if state.as_deref() != Some(self.state.as_str()) {
            // Not this login's redirect (a prefetch, a reload, another local process): answer it
            // and keep waiting, so a stray request cannot end the login.
            tracing::debug!("ignored a callback without the expected state");
            return page(StatusCode::BAD_REQUEST, PAGE_FAILED);
        }
        let (status, body, outcome) = if let Some(error) = error {
            let detail = description.map(|d| format!(": {d}")).unwrap_or_default();
            (
                StatusCode::OK,
                PAGE_FAILED,
                Err(Error::login(format!(
                    "the sign-in failed with `{error}`{detail}"
                ))),
            )
        } else if let Some(code) = code {
            (StatusCode::OK, PAGE_DONE, Ok(SecretString::from(code)))
        } else {
            (
                StatusCode::BAD_REQUEST,
                PAGE_FAILED,
                Err(Error::login(
                    "the sign-in redirect carried no authorization code",
                )),
            )
        };
        *self
            .outcome
            .lock()
            .expect("the outcome lock is never poisoned") = Some(outcome);
        page(status, body)
    }
}

fn page(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/html; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("a static response is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::ExposeSecret;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn get(port: u16, target: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        response
    }

    #[tokio::test]
    async fn returns_the_code_for_the_expected_state() {
        let loopback = Loopback::bind(None).await.unwrap();
        let port = loopback.port;
        assert_eq!(
            loopback.redirect_uri("/cb"),
            format!("http://127.0.0.1:{port}/cb")
        );
        let waiter = tokio::spawn(loopback.wait_for_code("/cb", "s1", Duration::from_secs(10)));
        // An idle connection and a stray path must not end the wait.
        let _idle = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        assert!(get(port, "/favicon.ico").await.starts_with("HTTP/1.1 404"));
        let response = get(port, "/cb?code=abc&state=s1").await;
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("Signed in"));
        let code = waiter.await.unwrap().unwrap();
        assert_eq!(code.expose_secret(), "abc");
    }

    #[tokio::test]
    async fn ignores_callbacks_without_the_expected_state() {
        let loopback = Loopback::bind(None).await.unwrap();
        let port = loopback.port;
        let waiter = tokio::spawn(loopback.wait_for_code("/cb", "s1", Duration::from_secs(10)));
        // A prefetch, a reloaded bookmark or another local process must not end the login.
        for stray in ["/cb", "/cb?code=abc&state=evil", "/cb?error=access_denied"] {
            assert!(
                get(port, stray).await.starts_with("HTTP/1.1 400"),
                "{stray}"
            );
        }
        assert!(!waiter.is_finished());
        assert!(
            get(port, "/cb?code=abc&state=s1")
                .await
                .starts_with("HTTP/1.1 200")
        );
        let code = waiter.await.unwrap().unwrap();
        assert_eq!(code.expose_secret(), "abc");
    }

    #[tokio::test]
    async fn reports_errors_from_the_authorization_server() {
        let loopback = Loopback::bind(None).await.unwrap();
        let port = loopback.port;
        let waiter = tokio::spawn(loopback.wait_for_code("/cb", "s1", Duration::from_secs(10)));
        get(
            port,
            "/cb?error=access_denied&error_description=nope&state=s1",
        )
        .await;
        let err = waiter.await.unwrap().unwrap_err();
        assert_eq!(
            err.to_string(),
            "the sign-in failed with `access_denied`: nope"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn times_out() {
        let loopback = Loopback::bind(None).await.unwrap();
        let err = loopback
            .wait_for_code("/cb", "s1", Duration::from_secs(600))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("600 seconds"), "{err}");
    }
}
