use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use serde::Deserialize;
use async_trait::async_trait;
use std::collections::HashSet;


pub struct CertSpotterScan {}

impl CertSpotterScan {
    pub fn new() -> Self {
        return CertSpotterScan {}
    }
}

impl Scanner for CertSpotterScan {
    fn name(&self) -> String {
        return String::from("CertSpotter subdomains scanner");
    }

    fn about(&self) -> String {
        return String::from("Use CertSpotter to find subdomains")
    }
}

/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct CertSpotterSubdomains {
    dns_names: Vec<String>
}


#[async_trait]
impl SubdomainScanner for CertSpotterScan {
    
}

