//! AWS partitions: the standard one, China and `GovCloud`, told apart by region name.

use url::Url;

use crate::domain::Region;
use crate::error::{Error, Result};

/// The sign-in and console hosts of a partition, known from any of its regions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub signin: &'static str,
    pub console: &'static str,
    /// Where STS is asked when a profile names no region.
    pub default_region: &'static str,
}

impl Partition {
    pub fn of(region: &Region) -> Self {
        let region = region.as_str();
        if region.starts_with("cn-") {
            Self {
                signin: "https://signin.amazonaws.cn/federation",
                console: "https://console.amazonaws.cn",
                default_region: "cn-north-1",
            }
        } else if region.starts_with("us-gov-") {
            Self {
                signin: "https://signin.amazonaws-us-gov.com/federation",
                console: "https://console.amazonaws-us-gov.com",
                default_region: "us-gov-west-1",
            }
        } else {
            Self {
                signin: "https://signin.aws.amazon.com/federation",
                console: "https://console.aws.amazon.com",
                default_region: "us-east-1",
            }
        }
    }

    /// The console page to land on: `destination` as a full URL, or as a path under the console
    /// (`s3/home`), else the console home. A region is added unless the page names one.
    pub fn destination(&self, destination: Option<&str>, region: Option<&Region>) -> Result<Url> {
        let mut url = match destination {
            Some(full) if full.starts_with("https://") => Url::parse(full).map_err(|err| {
                Error::usage(format!("--destination `{full}` is not a URL: {err}"))
            })?,
            Some(path) => Url::parse(&format!(
                "{}/{}",
                self.console,
                path.trim_start_matches('/')
            ))
            .map_err(|err| {
                Error::usage(format!(
                    "--destination `{path}` is not a console path: {err}"
                ))
            })?,
            None => Url::parse(&format!("{}/console/home", self.console)).expect("a valid URL"),
        };
        if let Some(region) = region
            && !url.query_pairs().any(|(key, _)| key == "region")
        {
            url.query_pairs_mut().append_pair("region", region.as_str());
        }
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(name: &str) -> Region {
        name.parse().unwrap()
    }

    #[test]
    fn picks_the_partition_from_a_region() {
        assert_eq!(
            Partition::of(&region("eu-west-1")).signin,
            "https://signin.aws.amazon.com/federation"
        );
        assert_eq!(
            Partition::of(&region("cn-north-1")).console,
            "https://console.amazonaws.cn"
        );
        assert_eq!(
            Partition::of(&region("us-gov-west-1")).signin,
            "https://signin.amazonaws-us-gov.com/federation"
        );
    }

    #[test]
    fn builds_the_destination() {
        let aws = Partition::of(&region("us-east-1"));
        let eu = region("eu-west-1");
        let page = |destination, region| aws.destination(destination, region).unwrap().to_string();
        assert_eq!(
            page(None, None),
            "https://console.aws.amazon.com/console/home"
        );
        assert_eq!(
            page(None, Some(&eu)),
            "https://console.aws.amazon.com/console/home?region=eu-west-1"
        );
        assert_eq!(
            page(Some("/s3/home"), Some(&eu)),
            "https://console.aws.amazon.com/s3/home?region=eu-west-1"
        );
        assert_eq!(
            page(
                Some("https://console.aws.amazon.com/ec2/home?region=us-east-2#Instances:"),
                Some(&eu)
            ),
            "https://console.aws.amazon.com/ec2/home?region=us-east-2#Instances:",
            "a page that names its region keeps it"
        );
        assert!(aws.destination(Some("https://"), None).is_err());
    }
}
