use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use serde::Deserialize;
use async_trait::async_trait;
use std::collections::HashSet;

pub struct ThreatcrowdScan {}

impl ThreatcrowdScan {
    pub fn new() -> Self {
        return ThreatcrowdScan {}
    }
}

impl Scanner for ThreatcrowdScan {
    fn name(&self) -> String {
        return String::from("Threatcrowd.org scanner");
    }

    fn about(&self) -> String {
        return String::from("Finds subdomains using Threatcrowd.org's online database.");
    }
}


/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct ThreatcrowdSubdomains {
    value: String
}


#[async_trait]
impl SubdomainScanner for ThreatcrowdScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {
        log::info!("Getting subdomains from threatcrowd.org...");

        let url = format!("https://threatcrowd.org/searchApi/v2/domain/report/?domain={}", target);
        let res = reqwest::get(&url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let threatcrowd_entries: Vec<ThreatcrowdSubdomains> = match res.json().await {
            Ok(info) => info,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name()))
        };
        
        // We use a hashset to prevent duplication of data
        let subdomains: HashSet<String> = threatcrowd_entries
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

