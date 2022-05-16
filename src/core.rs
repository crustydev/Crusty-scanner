use futures::{stream, StreamExt};
use reqwest::Client;

use std::collections::HashSet;
use std::iter::FromIterator;
use std::time::{Duration, Instant};

use crate::utils;
use crate::utils::Error;

use crate::scanners;
use crate::scanners::traits::CveScanner;
use crate::scanners::models::Subdomain;

pub fn list_scanners() {
    let cve_scanners = scanners::cve_scanners();
    let subdomain_scanners = scanners::subdomain_scanners();

    println!("\nSubdomain scanners:");
    for scanner in subdomain_scanners {
        println!("*    {}\n\t{}", scanner.name(), scanner.about());
    }

    println!("\n__________________________________________________________________________________________________________________");

    println!("\nCVE scanners:");
    for scanner in cve_scanners {
        println!("*    {}\n\t{}", scanner.name(), scanner.about());
    }
}

pub fn about() {
    println!("Welcome to crusty_scanner!\n");
    println!("Authored by: Fatoke Ademola Paul(crusty dev)");
    println!("Written in: The Rust Programming Language");
    println!("Inspiration drawn from: tricoder by Sylvain Kerkour");
    println!("What it does: Scans a target domain and its subdomains for vulnerabilities");
    println!("Enjoy using!");
}

pub fn help() {
    println!("Usage");
    println!("* enter 'cargo run scanners' to list scanners");
    println!("* enter 'cargo run about' to see details about this program");
    println!("* enter 'cargo run scan <target.com>' to scan target domain");
    println!("* enter 'cargo run help' to view help again\n");
}

pub fn scan(target: &str) -> Result<(), Error> {
    log::info!("\nScanning {} for its subdomains and vulnerabilities", target);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Building tokio's runtime");

    let http_timeout = Duration::from_secs(10);
    let http_client = Client::builder().timeout(http_timeout).build()?;
    let dns_resolver = utils::new_dns_resolver();

    let subdomains_concurrency = 100;
    let dns_concurrency = 200;
    let ports_concurrency = 200;
    //let vulnerabilities_concurrency = 20;
    let scan_start_time = Instant::now();

    let subdomains_modules = scanners::subdomain_scanners();

    runtime.block_on(async move {
        // Scan subdomains using all the different scanners in the subdomain scanner module
        // and collect the results into a single String vector.

        let mut subdomains: Vec<String> = stream::iter(subdomains_modules.into_iter())
            .map(|module| async move {
                match module.get_subdomains(target).await {
                    Ok(new_subdomains) => Some(new_subdomains),
                    Err(err) => {
                        log::error!("subdomains/{}: {}", module.name(), err);
                        None
                    }
                }
            })
            .buffer_unordered(subdomains_concurrency)
            .filter_map(|domain| async { domain })
            .collect::<Vec<Vec<String>>>()
            .await
            .into_iter()
            .flatten()
            .collect();

        subdomains.push(target.to_string());

        // Clean results using a hashset to prevent duplicates.
        // 
        let subdomains: Vec<Subdomain> = HashSet::<String>::from_iter(subdomains.into_iter())
            .into_iter()
            .filter(|subdomain| subdomain.contains(target))
            .map(|domain| Subdomain {
                domain_name: domain,
                open_ports: Vec::new(),
            })
            .collect();

        log::info!("Found {} possible domains.", subdomains.len());

        // Concurrently filter out domains that do not resolve according the Domain Naming System.
        // 
        let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
            .map(|domain| utils::resolve_dns(&dns_resolver, domain))
            .buffer_unordered(dns_concurrency)
            .filter_map(|domain| async move { domain })
            .collect()
            .await;

        log::info!("Found {} domains that resolve!", subdomains.len());

        // Scan each subdomain for its open ports
        // 
        let subdomains: Vec<Subdomain> = stream::iter(subdomains.into_iter())
            .map(|domain| {
                log::info!("Scanning ports for {}", &domain.domain_name);
                utils::scan_ports(ports_concurrency, domain)
            })
            .buffer_unordered(1)
            .collect()
            .await;

        for subdomain in &subdomains {
            println!("{}", subdomain.domain_name);
            for port in &subdomain.open_ports {
                println!("    {}", port.port);
            }
        }


        /*
        println!("---------------------- Vulnerabilities ----------------------");

        // Scan each socket address for vulnerabilities
        // 

        let mut targets: Vec<(Box<dyn CveScanner>, String)> = Vec::new();
        for subdomain in subdomains {
            for port in subdomain.open_ports {
                let cve_scanners = scanners::cve_scanners();
                for cve_scanner in cve_scanners {
                    let target = format!("http://{}:{}", &subdomain.domain_name, port.port);
                    targets.push((cve_scanner, target));
                }
            }
        }

        stream::iter(targets.into_iter())
            .for_each_concurrent(vulnerabilities_concurrency, |(scanner, target)| {
                let http_client = http_client.clone();
                async move {
                    match scanner.scan(&http_client, &target).await {
                        Ok(Some(finding)) => println!("{:?}", &finding),
                        Ok(None) => {}
                        Err(err) => log::debug!("Error: {}", err),
                    };
                }
            })
            .await;
        */
    });

    let scan_duration = scan_start_time.elapsed();
    log::info!("Scan completed in {:?}", scan_duration);

    Ok(())
    
}