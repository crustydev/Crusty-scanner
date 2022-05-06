use crate::{
    scanners::CveScanResult,
    scanners::traits::{Scanner, CveScanner},
    Error,
};

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

pub struct ElasticsearchScan {}

impl ElasticsearchScan {
    pub fn new() -> Self {
        ElasticsearchScan {}
    }
}

impl Scanner for ElasticsearchScan {
    fn name(&self) -> String {
        String::from("Elastic search vulnerability scanner")
    }

    fn about(&self) -> String {
        String::from("Scans address for Elastic search unauthenticated access")
    }
}

#[derive(Clone, Debug, Deserialize)]
struct ElasticsearchJson {
    pub name: String,
    pub cluster_name: String,
    pub tagline: String,
}

#[async_trait]
impl CveScanner for ElasticsearchScan {
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

        let info: ElasticsearchJson = match res.json().await {
            Ok(info) => info,
            Err(_) => return Ok(None), // JSON is not valid, so not an elastisearch server
        };

        if info.tagline.to_lowercase().contains("you know, for search") {
            return Ok(Some(CveScanResult::ElasticsearchUnauthenticatedAccess(url)));
        }

        Ok(None)
    }
}
