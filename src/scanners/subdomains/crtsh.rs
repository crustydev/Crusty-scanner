use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use serde::Deserialize;
use async_trait::async_trait;
use std::collections::HashSet;


pub struct CrtShScan {}

impl CrtShScan {
    pub fn new() -> Self {
        return CrtShScan {};
    }
}

impl Scanner for CrtShScan {
    fn name(&self) -> String {
        return String::from("crt.sh subdomains scan");
    }

    fn about(&self) -> String {
        return String::from("Finding subdomains using crt.sh's online list..");
    }
}

/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct CrtShSubdomains {
    value: String
}

#[async_trait]
impl SubdomainScanner for CrtShScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {
        log::info!("Getting subdomains from crt.sh...");

        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        let res = reqwest::get(&url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let crtsh_entries: Vec<CrtShSubdomains> = match res.json().await {
            Ok(info) => info,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name())),
        };

        // We use a hashset to prevent duplication of data
        let subdomains: HashSet<String> = crtsh_entries
            .into_iter()
            .map(|entry| {
                entry
                    .name_value
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