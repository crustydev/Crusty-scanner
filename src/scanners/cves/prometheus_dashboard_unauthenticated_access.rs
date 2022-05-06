use crate::{
    scanners::CveScanResult,
    scanners::traits::{Scanner, CveScanner},
    Error,
};

use async_trait::async_trait;
use reqwest::Client;

/// Scans to see if Prometheus Dashboard is open to unauthenticated access
pub struct PrometheusDashboardScan {}

impl PrometheusDashboardScan {
    pub fn new() -> Self {
        return PrometheusDashboardScan {};
    }
}

impl Scanner for PrometheusDashboardScan {
    fn name(&self) -> String {
        String::from("Prometheus Dashboard vulnerability scan")
    }

    fn about(&self) -> String {
        String::from("Scans to see if Prometheus Dashboard is open to unauthenticated access")
    }
}

#[async_trait]
impl CveScanner for PrometheusDashboardScan {
    async fn scan(
        &self,
        http_client: &Client,
        endpoint: &str,
    ) -> Result<Option<CveScanResult>, Error> {
        let url = format!("{}", &endpoint);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.text().await?;
        if body
            .contains(r#"<title>Prometheus Time Series Collection and Processing Server</title>"#)
        {
            return Ok(Some(CveScanResult::PrometheusOpenDashboard(url)));
        }

        Ok(None)
    }
}
