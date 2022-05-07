use crate::ports_list::PORTS_LIST;

use futures::StreamExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::scanners::models::{Subdomain, Port};

use thiserror::Error;
use trust_dns_resolver::{
    AsyncResolver,
    config::{ResolverOpts, ResolverConfig},
    name_server::{TokioRuntime, GenericConnection, GenericConnectionProvider}
};

pub type Resolver = Arc<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>;


/// This function takes in a Subdomain, scans it for ports for which connections
/// are active, and returns the subdomain with a vector of its active ports.
/// 
pub async fn scan_ports(concurrency: usize, subdomain: Subdomain) -> Subdomain {
    log::info!("Scanning subdomain: {} for open ports....", &subdomain.domain_name);

    let mut result = subdomain.clone();

    let socket_addresses: Vec<SocketAddr> = format!("{}:1024", subdomain.domain_name)
        .to_socket_addrs()
        .expect("Scanning port...Creating socket address failed")
        .collect();
    
    // If no socket address is created for the subdomain over port 1024, return 
    // the subdomain as it is with open_ports empty.

    if socket_addresses.len() == 0 {
        return subdomain;
    }

    let address = socket_addresses[0];

    // use channels to create concurrent streams (concept of a worker pool in Rust)
    let (input_tx, input_rx) = mpsc::channel(concurrency);
    let (output_tx, output_rx) = mpsc::channel(concurrency);

    tokio::spawn(async move {
        for port in PORTS_LIST {
            let _ = input_tx.send(*port).await;
        }
    });

    let input_receiver_stream = tokio_stream::wrappers::ReceiverStream::new(input_rx);
    input_receiver_stream
        .for_each_concurrent(concurrency, |port| {
            let output_tx = output_tx.clone();
            async move {
                let port = scan_port(address, port).await;
                if port.conn_open {
                    let _ = output_tx.send(port).await;
                }
            }
        }).await;

        drop(output_tx);

    let output_receiver_stream = tokio_stream::wrappers::ReceiverStream::new(output_rx);
    result.open_ports = output_receiver_stream.collect().await;

    return result;
}

/// Checks if a TcpConnection is accepted for a socket address over a particular
/// port.
///  
async fn scan_port(mut socket_address: SocketAddr, port: u16) -> Port {
    let timeout = Duration::from_secs(5);

    socket_address.set_port(port);

    let is_open = matches!(
        tokio::time::timeout(timeout, TcpStream::connect(&socket_address)).await,
        Ok(Ok(_)),
    );

    return Port {
        port: port,
        conn_open: is_open,
    }
}

/// Creates a new trust_dns_resolver
pub fn new_dns_resolver() -> Resolver {
    log::info!("Generating dns resolver...");

    let resolver = AsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts {
            timeout: Duration::from_secs(4),
            ..Default::default()
        },
    ).expect("Building dns resolver failed!");

    return Arc::new(resolver);
}

/// Check to see if a subdomain resolves according to the Domain Naming System
pub async fn resolve_dns(dns_resolver: &Resolver, subdomain: Subdomain) -> Option<Subdomain> {
    match &dns_resolver.lookup_ip(subdomain.domain_name.as_str()).await.is_ok() {
        true => Some(subdomain),
        false => None
    }
}

/// Struct for error reporting.
/// 
#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("{0}, Invalid HTTP response")]
    InvalidHttpResponse(String),
    #[error("{0}, Reqwest Error")]
    ReqwestError(String),
    #[error("{0}, Tokio Error")]
    TokioJoinError(String),
}

/// Converts tokioJoinError to custom enum Error for uniform reporting
/// 
impl std::convert::From<tokio::task::JoinError> for Error {
    fn from(error_message: tokio::task::JoinError) -> Self {
        return Error::TokioJoinError(error_message.to_string());
    }
}

/// Converts reqwestError to custom enum Error for uniform reporting
impl std::convert::From<reqwest::Error> for Error {
    fn from(error_message: reqwest::Error) -> Self {
        return Error::ReqwestError(error_message.to_string());
    }
}
