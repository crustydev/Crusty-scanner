use crate::scanners::traits::{Scanner, SubdomainScanner};

pub struct BruteForceScan {}

impl BruteForceScan {
    pub fn new() -> Self {
        return BruteForceScan{};
    }
}

impl Scanner for BruteForceScan {
    fn name(&self) -> String {
        return String::from("Brute force subdomain scan");
    }

    fn about(&self) -> String {
        return String::from("Find subdomains using bruteforce from wordlist");
    }
}


#[async_trait]
impl SubdomainScanner for BruteForceScan {
    
}