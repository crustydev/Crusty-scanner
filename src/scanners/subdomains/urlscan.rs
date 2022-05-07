use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use serde::Deserialize;
use async_trait::async_trait;
use std::collections::HashSet;


pub struct UrlScan {}

impl UrlScan {
    pub fn new() -> Self {
        return UrlScan {};
    }
}

impl Scanner for UrlScan {
    fn name(&self) -> String {
        return String::from("Urlscan.io scanner");
    }

    fn about(&self) -> String {
        return String::from("Finds subdomains using data from urlscan.io.");
    }
}

/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct UrlScanResponse {
    value: String
}

#[async_trait]
impl SubdomainScanner for UrlScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {
        log::info!("Getting subdomains from crt.sh...");

        let url = format!("https://url.scan.io/api/v1/search/?q=domain:{}", target);
        let res = reqwest::get(&url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let results: Vec<UrlScanResponse> = match res.json().await {
            Ok(info) => info,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
        };

        // We use a hashset to prevent duplication of data
        let subdomains: HashSet<String> = results
            .into_iter()
            .map(|entry| {
                entry
                    .value
                    .split("\n")
                    .map(|subdomain| subdomain.trim().to_string())
                    .collect::<Vec<String>>()
            })
            .flatten()
            .filter(|subdomain: &String| !subdomain.contains("*"))
            .collect();

        Ok(subdomains.into_iter().collect())

    }
}