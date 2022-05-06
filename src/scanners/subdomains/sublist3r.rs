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
        return String::from("Sublist3r subdomains scanner");
    }

    fn about(&self) -> String {
        return String::from("Use Sublist3r to find subdomains")
    }
}

/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct Sublist3rSubdomains {
    subdomains: Vec<String>
}


#[async_trait]
impl SubdomainScanner for Sublist3rScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {
        
    }

}