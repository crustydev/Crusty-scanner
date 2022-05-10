pub mod traits;
use traits::CveScanner;
use traits::SubdomainScanner;
pub mod models;

mod subdomains;
mod cves;

pub fn cve_scanners() -> Vec<Box<dyn CveScanner>> {
    return vec![
        Box::new(cves::DotEnvScan::new()),
        Box::new(cves::DsStoreScan::new()),
        Box::new(cves::ElasticsearchScan::new()),
        Box::new(cves::GitlabOpenScan::new()),
        Box::new(cves::PrometheusDashboardScan::new())
    ]
}


// Can't get webarchive scan to work for some reason
pub fn subdomain_scanners() -> Vec<Box<dyn SubdomainScanner>> {
    return vec![
        Box::new(subdomains::BruteForceScan::new()),
        Box::new(subdomains::CrtShScan::new()),
        Box::new(subdomains::ThreatCrowdScan::new()),
        Box::new(subdomains::ThreatMinerScan::new()),
        //Box::new(subdomains::WebArchiveScan::new())
    ];
}

#[derive(Debug, Clone)]
pub enum CveScanResult {
    DotEnvFileDisclosure(String),
    DSStoreFileDisclosure(String),
    ElasticsearchUnauthenticatedAccess(String),
    GitlabOpenRegistration(String),
    PrometheusOpenDashboard(String)
}