use async_trait::async_trait;
use reqwest::Client;

use crate::utils::Error;
use super::CveScanResult;

/// Scanner trait
pub trait Scanner {
    fn name(&self) -> String;
    fn about(&self) -> String;
}


/// SubdomainScanner trait. Required that the type implements the Scanner trait.
#[async_trait]
pub trait SubdomainScanner: Scanner {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error>;
}


/// CveScanner trait. Required that the type implements the Scanner trait.
#[async_trait]
pub trait CveScanner: Scanner {
    async fn scan(&self, http_client: &Client, endpoint: &str)
        -> Result<Option<CveScanResult>, Error>;
}