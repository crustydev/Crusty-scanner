# Crusty-scanner v1

Subdomain enumeration tool written in RustLang for asset discovery in security reconaissance.


## About

This is an asynchronous Rust program that runs on the Tokio.rs runtime, taking in a target domain and using a variety of sources to retrieve its subdomains. For each subdomain it finds, it scans to check what ports for which a connection can be opened over the subdomain. It returns a list of open ports for each subdomain.


## Usage

To scan a target domain:  
`cargo run scan <target_domain>`  
for example:  
`cargo run scan google.com`  


To list scanners:  
`cargo run scanners`


To get help messages:
`cargo run help`


This program displays to the console 


Detailed vulnerability search feature coming soon. V1 does subdomain enumeration only.




