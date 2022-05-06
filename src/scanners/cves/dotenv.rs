use crate::{
    scanners::CveScanResult,
    scanners::traits::{Scanner, CveScanner},
    Error
};

use async_trait::async_trait;
use reqwest::Client;


pub struct DotEnvScan {}

impl DotEnvScan {
    pub fn new() -> Self {
        DotEnvScan {}
    }
}

impl Scanner for DotEnvScan {
    fn name(&self) -> String {
        String::from(".env vulnerability scanner")
    }

    fn about(&self) -> String {
        String::from("Checks to see if there's a .env file disclosure")
    }
}

#[async_trait]
impl CveScanner for DotEnvScan {
    async fn scan(
        &self,
        http_client: &Client,
        endpoint: &str,
    ) -> Result<Option<CveScanResult>, Error> {
        let url = format!("{}/.env", &endpoint);
        let res = http_client.get(&url).send().await?;

        if res.status().is_success() {
            return Ok(Some(CveScanResult::DotEnvFileDisclosure(url)));
        }

        Ok(None)
    }
}
