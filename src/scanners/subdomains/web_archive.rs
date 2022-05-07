use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashSet;
use url::Url;

pub struct WebArchiveScan {}

impl WebArchiveScan {
    pub fn new() -> Self {
        return WebArchiveScan {};
    }
}

impl Scanner for WebArchiveScan {
    fn name(&self) -> String {
        return String::from("Web.archive.org subdomains scan");
    }

    fn about(&self) -> String {
        return String::from("Finds subdomains using web.archive.org's online database search.");
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WebArchiveResults {
    results: Vec<Vec<String>>
}

#[async_trait]
impl SubdomainScanner for WebArchiveScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {
        let url = format!("https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&output=json&collapse=urlkey&url={}", target);
        let res = reqwest::get(&url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let web_archive_urls: WebArchiveResults = match res.json().await {
            Ok(info) => info,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
        };

        let subdomains: HashSet<String> = web_archive_urls.results
            .into_iter()
            .flatten()
            .filter_map(|url| {
                Url::parse(&url)
                    .map_err(|err| {
                        log::error!("{}: error parsing url: {}", self.name(), err);
                        err
                    })
                    .ok()
            })
            .filter_map(|url| url.host_str().map(|host| host.to_string()))
            .collect();

        Ok(subdomains.into_iter().collect())
    }
}