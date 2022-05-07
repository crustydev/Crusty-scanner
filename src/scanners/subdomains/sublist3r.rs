use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use serde::Deserialize;
use async_trait::async_trait;
use std::collections::HashSet;


pub struct Sublist3rScan {}

impl Sublist3rScan {
    pub fn new() -> Self {
        return Sublist3rScan {}
    }
}

impl Scanner for Sublist3rScan {
    fn name(&self) -> String {
        return String::from("Sublist3r.com scanner");
    }

    fn about(&self) -> String {
        return String::from("Finds subdomains using Sublist3r.com's online database.")
    }
}

/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct Sublist3rSubdomains {
    subdomain: String
}


#[async_trait]
impl SubdomainScanner for Sublist3rScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {
        log::info!("Getting subdomains from sublist3r.com...");

        let url = format!("https://api.sublist3r.com/search.php?domain={}", target);
        let res = reqwest::get(&url).await?;

        if !res.status().is_success() {
            return Err(Error::InvalidHttpResponse(self.name()));
        }

        let threatcrowd_entries: Vec<Sublist3rSubdomains> = match res.json().await {
            Ok(result) => result,
            Err(_) => return Err(Error::InvalidHttpResponse(self.name()))
        };

        let subdomains: HashSet<String> = threatcrowd_entries
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
