pub mod traits;
use traits::SubdomainScanner;
pub mod models;

mod subdomains;


// Can't get webarchive scan to work
pub fn subdomain_scanners() -> Vec<Box<dyn SubdomainScanner>> {
    return vec![
        //Box::new(subdomains::BruteForceScan::new()),
        //Box::new(subdomains::CrtShScan::new()),
        Box::new(subdomains::ThreatCrowdScan::new()),
        Box::new(subdomains::ThreatMinerScan::new()),
        //Box::new(subdomains::WebArchiveScan::new()),
    ];
}

