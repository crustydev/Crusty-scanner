use crate::{
    scanners::CveScanResult,
    scanners::traits::{Scanner, CveScanner},
    utils::Error,
};

use async_trait::async_trait;
use reqwest::Client;

pub struct GitlabOpenScan {}

impl GitlabOpenScan {
    pub fn new() -> Self {
        return GitlabOpenScan {};
    }
}

impl Scanner for GitlabOpenScan {
    fn name(&self) -> String {
        String::from("Gitlab open registration scanner.")
    }

    fn about(&self) -> String {
        String::from("Scans to see if a GitLab instance is open to registrations.")
    }
}

#[async_trait]
impl CveScanner for GitlabOpenScan {
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
        if body.contains("This is a self-managed instance of GitLab") && body.contains("Register") {
            return Ok(Some(CveScanResult::GitlabOpenRegistration(url)));
        }

        Ok(None)
    }
}
