//! Shared AWS SDK configuration. Loading through `aws-config` keeps the SDK's endpoint
//! resolution (FIPS, dual-stack, `AWS_ENDPOINT_URL_SSO[_OIDC]`), proxy settings and retries.

use std::time::Duration;

use aws_config::retry::RetryConfig;
use aws_config::timeout::TimeoutConfig;
use aws_config::{AppName, BehaviorVersion, SdkConfig};

use crate::domain::Region;

/// How long one attempt may wait for an answer before it is retried. Identity Center answers in
/// well under a second; without a limit, an endpoint that accepts the connection and never
/// answers (a broken proxy or VPN route) hangs gac for good.
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a call may take with its retries. A throttled portal call finishes within its
/// 20 attempts and 1 s backoff cap (`portal::MAX_ATTEMPTS`, `portal::MAX_BACKOFF`) in far less.
const OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

/// SDK settings for the unsigned Identity Center APIs in `region`, with adaptive retry and the
/// timeouts above; the SDK's default connect timeout still applies. The portal client tunes it
/// further for its throttled fan-out (`portal::client_config`).
pub async fn load(region: &Region) -> SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .app_name(AppName::new("gac-redux").expect("a valid app name"))
        .region(aws_config::Region::new(region.as_str().to_owned()))
        .no_credentials()
        .retry_config(RetryConfig::adaptive())
        .timeout_config(
            TimeoutConfig::builder()
                .operation_attempt_timeout(ATTEMPT_TIMEOUT)
                .operation_timeout(OPERATION_TIMEOUT)
                .build(),
        )
        .load()
        .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::error::{self, Error};

    // Regression: #79 - an endpoint that accepted the connection and never answered hung forever
    #[tokio::test(start_paused = true)]
    async fn gives_up_on_an_endpoint_that_never_answers() {
        // Accepts every connection and holds it open without a byte of response.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&accepted);
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                held.push(stream);
            }
        });

        let sdk = load(&"us-east-1".parse().unwrap()).await;
        let config = aws_sdk_ssooidc::config::Builder::from(&sdk)
            .endpoint_url(endpoint)
            .build();
        let client = aws_sdk_ssooidc::Client::from_conf(config);
        let outcome = tokio::time::timeout(
            Duration::from_secs(600),
            client
                .register_client()
                .client_name("gac-redux")
                .client_type("public")
                .send(),
        )
        .await
        .expect("the call gives up well within 10 minutes");
        let err = error::service("RegisterClient", &outcome.unwrap_err());
        assert!(matches!(err, Error::Unreachable { .. }), "{err}");
        // The connection was made, so the read, not the connect, timed out.
        assert!(accepted.load(Ordering::SeqCst) >= 1);
    }
}
