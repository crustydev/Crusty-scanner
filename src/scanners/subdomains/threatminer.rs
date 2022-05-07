use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use serde::Deserialize;
use async_trait::async_trait;
use std::collections::HashSet;


pub struct ThreatMinerScan {}

impl ThreatMinerScan {
    pub fn new() -> Self {
        return ThreatMinerScan {}
    }
}

impl Scanner for ThreatMinerScan {
    fn name(&self) -> String {
        return String::from("Threatminer scanner");
    }

    fn about(&self) -> String {
        return String::from("Finds subdomains using threatminer.org's online api.")
    }
}

/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct ThreatMinerSubdomains {
    subdomain: String
}


#[async_trait]
impl SubdomainScanner for ThreatMinerScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {
        log::info!("Getting subdomains from threatminer.org...");

        let url = format!("https://api.threatminer.org/v2/domain.php?q={}&api=True&rt=5", target);
        let res = reqwest::get(&url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let threatminer_entries: Vec<ThreatMinerSubdomains> = match res.json().await {
            Ok(info) => info,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name()))
        };

        // we use a hashset to prevent duplication of data
        let subdomains: HashSet<String> = threatminer_entries
            .into_iter()
            .map(|entry| {
                entry
                    .subdomain
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

