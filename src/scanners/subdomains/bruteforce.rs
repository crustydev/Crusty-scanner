use crate::scanners::traits::{Scanner, SubdomainScanner};
use crate::utils::Error;

use std::{
    fs::File,
    io::{BufRead, BufReader},
    time::Instant
};

use async_trait::async_trait;
use tokio::sync::mpsc;
use futures::StreamExt;



pub struct BruteForceScan {}

impl BruteForceScan {
    pub fn new() -> Self {
        return BruteForceScan{};
    }
}

impl Scanner for BruteForceScan {
    fn name(&self) -> String {
        return String::from("Brute force scanner");
    }

    fn about(&self) -> String {
        return String::from("Finds subdomains using bruteforce.");
    }
}


#[async_trait]
impl SubdomainScanner for BruteForceScan {
    async fn get_subdomains(&self, target: &str) -> Result<Vec<String>, Error> {

        let concurrency: usize = 200;
        let subdomains_file = File::open("subdomainlist.txt")
            .expect("subdomainlist.txt: open failed for bruteforce subdomain scan");

        let reader = BufReader::new(subdomains_file);

        let start_time = Instant::now();
        
        let(input_tx, input_rx) = mpsc::channel(concurrency);
        let(output_tx, output_rx) = mpsc::channel(concurrency);

        tokio::spawn(async move {
            for line in reader.lines() {
                let _ = input_tx.send(line).await;
            }
        });

        let input_rx_stream = tokio_stream::wrappers::ReceiverStream::new(input_rx);
        input_rx_stream
            .for_each_concurrent(concurrency, |prefix| {
                let output_tx = output_tx.clone();
                let prefix = prefix.unwrap();
                async move {
                    let subdomain = format!("{}.{}", prefix, &target);
                    let _ = output_tx.send(subdomain).await; 
                }
            })
            .await;

        //close channel
        drop(output_tx);

        let output_rx_stream = tokio_stream::wrappers::ReceiverStream::new(output_rx);
        let subdomains = output_rx_stream.collect().await;

        let _scan_duration = start_time.elapsed();

        log::info!("\nBruteforce subdomain scan. time elapsed: {:?}", _scan_duration);
        return Ok(subdomains);
    
    }
    
}