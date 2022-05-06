use crate::{
    scanners::traits::{Scanner, SubdomainScanner},
    utils::Error
};

use serde::Deserialize;
use async_trait::async_trait;
use std::collections::HashSet;


pub struct SecurityTrailsScan {}

impl SecurityTrailsScan {
    pub fn new() -> Self {
        return SecurityTrailsScan {}
    }
}

impl Scanner for SecurityTrailsScan {
    fn name(&self) -> String {
        return String::from("Securitytrails subdomains scanner");
    }

    fn about(&self) -> String {
        return String::from("Use Security trails to find subdomains")
    }
}


/// Json deserialization struct for retrieving results from response body
/// 
#[derive(Clone, Debug, Deserialize)]
struct SecurityTrailsSubdomains {
    subdomains: Vec<String>
}


#[async_trait]
impl SubdomainScanner for SecurityTrailsScan {

}