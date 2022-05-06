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

pub fn subdomain_scanners() -> Vec<Box<dyn SubdomainScanner>> {
    return vec![
        Box::new(subdomains::BruteForceScan::new()),
        Box::new(subdomains::CertSpotterScan::new()),
        Box::new(subdomains::CrtShScan::new()),
        Box::new(subdomains::SecurityTrailsScan::new()),
        Box::new(subdomains::Sublist3rScan::new()),
        Box::new(subdomains::WebArchiveScan::new())
    ];
}

#[derive(Debug, Clone)]
pub enum CveScanResult {
    DotEnvFileDisclosure(String),
    DSStoreDisclosure(String),
    ElasticsearchUnauthenticatedAccess(String),
    GitlabOpenRegistration(String),
    PrometheusOpenDashboard(String)
}