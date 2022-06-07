## Crusty-scanner v1

Subdomain enumeration tool written in RustLang for asset discovery in security reconaissance.


### About

This is an asynchronous Rust program that runs on the Tokio.rs runtime, taking in a target domain and using a variety of sources to retrieve its subdomains. For each subdomain it finds, it scans to check what ports for which a connection can be opened over the subdomain. It returns a list of open ports for each subdomain.


### Prerequisites

Make sure to have rustc and cargo installed on your pc. You can get a functional setup by following the steps [here](https://doc.rust-lang.org/book/ch01-01-installation.html)


### Usage

Change into the project directory containing Cargo.toml.

To scan a target domain:
```sh
cargo run scan <target_domain>
```
for example:
```sh  
cargo run scan google.com
```  

To list scanners:  
```sh
cargo run scanners
```

To get help messages:
```sh
cargo run help
```

This program displays each of the target's subdomains and their open ports to the console.

Have fun!





