//! Shared AWS SDK configuration. Loading through `aws-config` keeps the SDK's endpoint
//! resolution (FIPS, dual-stack, `AWS_ENDPOINT_URL_SSO[_OIDC]`), proxy settings and retries.

use aws_config::retry::RetryConfig;
use aws_config::{AppName, BehaviorVersion, SdkConfig};

use crate::domain::Region;

/// SDK settings for the unsigned Identity Center APIs in `region`. Adaptive retry was the only
/// setup that stayed robust when the portal throttles a fan-out.
pub async fn load(region: &Region) -> SdkConfig {
    aws_config::defaults(BehaviorVersion::latest())
        .app_name(AppName::new("gac").expect("a valid app name"))
        .region(aws_config::Region::new(region.as_str().to_owned()))
        .no_credentials()
        .retry_config(RetryConfig::adaptive())
        .load()
        .await
}
