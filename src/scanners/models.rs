#[derive(Debug, Clone)]
pub struct Port {
    pub port: u16,
    pub conn_open: bool
}

#[derive(Debug, Clone)]
pub struct Subdomain {
    pub domain_name: String,
    pub open_ports: Vec<Port>,
}

