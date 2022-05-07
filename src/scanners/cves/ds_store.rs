use crate::{
    scanners::CveScanResult,
    scanners::traits::{Scanner, CveScanner},
    utils::Error,
};

use async_trait::async_trait;
use reqwest::Client;

pub struct DsStoreScan {}

impl DsStoreScan {
    pub fn new() -> Self {
        DsStoreScan {}
    }

    pub fn is_ds_store_file(&self, content: &[u8]) -> bool {
        if content.len() < 8 {
            return false;
        }

        let signature = [0x0, 0x0, 0x0, 0x1, 0x42, 0x75, 0x64, 0x31];

        return content[0..8] == signature;
    }
}

impl Scanner for DsStoreScan {
    fn name(&self) -> String {
        String::from("Ds_store scanner")
    }

    fn about(&self) -> String {
        String::from("Scans for a DsStore disclosure.")
    }
}

#[async_trait]
impl CveScanner for DsStoreScan {
    async fn scan(
        &self,
        http_client: &Client,
        endpoint: &str,
    ) -> Result<Option<CveScanResult>, Error> {
        let url = format!("{}/.DS_Store", &endpoint);
        let res = http_client.get(&url).send().await?;

        if !res.status().is_success() {
            return Ok(None);
        }

        let body = res.bytes().await?;
        if self.is_ds_store_file(&body.as_ref()) {
            return Ok(Some(CveScanResult::DSStoreFileDisclosure(url)));
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_ds_store() {
        let module = super::DsStoreScan::new();
        let body = "testtesttest";
        let body2 = [
            0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00,
            0x08, 0x0,
        ];

        assert_eq!(false, module.is_ds_store_file(body.as_bytes()));
        assert_eq!(true, module.is_ds_store_file(&body2));
    }
}
