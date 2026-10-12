use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use rustls::{ClientConfig, ClientConnection, RootCertStore, pki_types::ServerName};
use std::{
    env,
    io::{Read, Write},
    net::{TcpStream, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use x509_parser::{extensions::GeneralName, prelude::*};

#[derive(Clone, Debug)]
pub struct TlsReport {
    pub subject: String,
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub protocol: String,
    pub cipher: String,
    pub serial: String,
    pub chain_length: usize,
}

pub fn inspect_tls(host: &str, port: u16) -> Result<TlsReport> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        let _ = roots.add(certificate);
    }
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_string()).context("invalid TLS server name")?;
    let mut connection = ClientConnection::new(Arc::new(config), name)?;
    let mut socket = connect(host, port)?;
    socket.set_read_timeout(Some(Duration::from_secs(8)))?;
    socket.set_write_timeout(Some(Duration::from_secs(8)))?;
    while connection.is_handshaking() {
        connection.complete_io(&mut socket)?;
    }
    let protocol = connection
        .protocol_version()
        .map(|version| format!("{version:?}").replace('_', "."))
        .unwrap_or_else(|| "unknown".into());
    let cipher = connection
        .negotiated_cipher_suite()
        .map(|suite| format!("{:?}", suite.suite()))
        .unwrap_or_else(|| "unknown".into());
    let chain = connection
        .peer_certificates()
        .ok_or_else(|| anyhow!("TLS peer supplied no certificate chain"))?;
    let leaf = chain
        .first()
        .ok_or_else(|| anyhow!("TLS peer supplied an empty certificate chain"))?;
    let (_, certificate) = X509Certificate::from_der(leaf.as_ref())
        .map_err(|error| anyhow!("cannot parse TLS certificate: {error}"))?;
    let mut dns_names = Vec::new();
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        for name in &extension.value.general_names {
            if let GeneralName::DNSName(name) = name {
                dns_names.push((*name).to_string());
            }
        }
    }
    dns_names.sort();
    dns_names.dedup();
    Ok(TlsReport {
        subject: certificate.subject().to_string(),
        issuer: certificate.issuer().to_string(),
        dns_names,
        not_before: certificate.validity().not_before.to_datetime().to_string(),
        not_after: certificate.validity().not_after.to_datetime().to_string(),
        protocol,
        cipher,
        serial: certificate.raw_serial_as_string(),
        chain_length: chain.len(),
    })
}

fn connect(host: &str, port: u16) -> Result<TcpStream> {
    if let Some(proxy) = proxy_for(host)? {
        return connect_proxy(&proxy, host, port);
    }
    connect_direct(host, port)
}

fn connect_direct(host: &str, port: u16) -> Result<TcpStream> {
    let addresses: Vec<_> = (host, port).to_socket_addrs()?.collect();
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, Duration::from_secs(6)) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(Into::into)
        .unwrap_or_else(|| anyhow!("TLS host resolved to no addresses")))
}

fn proxy_for(host: &str) -> Result<Option<url::Url>> {
    let bypassed = env::var("NO_PROXY")
        .or_else(|_| env::var("no_proxy"))
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .any(|entry| {
            entry == "*"
                || entry == host
                || entry
                    .strip_prefix('.')
                    .is_some_and(|suffix| host.ends_with(suffix))
        });
    if bypassed {
        return Ok(None);
    }
    let Some(value) = env::var("HTTPS_PROXY")
        .or_else(|_| env::var("https_proxy"))
        .ok()
    else {
        return Ok(None);
    };
    let proxy = url::Url::parse(&value).context("invalid HTTPS proxy URL")?;
    if proxy.scheme() != "http" {
        return Err(anyhow!("only HTTP CONNECT proxies are supported for TLS"));
    }
    Ok(Some(proxy))
}

fn connect_proxy(proxy: &url::Url, host: &str, port: u16) -> Result<TcpStream> {
    let proxy_host = proxy.host_str().context("HTTPS proxy has no host")?;
    let proxy_port = proxy.port_or_known_default().unwrap_or(80);
    let mut stream = connect_direct(proxy_host, proxy_port)?;
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    let authorization = if proxy.username().is_empty() {
        String::new()
    } else {
        let credentials = format!("{}:{}", proxy.username(), proxy.password().unwrap_or(""));
        format!(
            "Proxy-Authorization: Basic {}\r\n",
            STANDARD.encode(credentials)
        )
    };
    write!(
        stream,
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n{authorization}Connection: keep-alive\r\n\r\n"
    )?;
    stream.flush()?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while response.len() < 16 * 1024 && !response.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte)? == 0 {
            break;
        }
        response.push(byte[0]);
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(anyhow!(
            "HTTPS proxy returned an incomplete CONNECT response"
        ));
    }
    let status = String::from_utf8_lossy(&response);
    let accepted = status
        .lines()
        .next()
        .is_some_and(|line| line.split_whitespace().nth(1) == Some("200"));
    if !accepted {
        return Err(anyhow!(
            "HTTPS proxy rejected CONNECT without exposing response details"
        ));
    }
    Ok(stream)
}
