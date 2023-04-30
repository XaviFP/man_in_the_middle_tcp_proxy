use anyhow::Result;
use argh::FromArgs;
use rustls_pemfile::{certs, rsa_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{self, split, stdout, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{
    self, Certificate, ClientConfig, OwnedTrustAnchor, PrivateKey, RootCertStore, ServerName,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

///
#[derive(FromArgs)]
struct Options {
    /// bind addr
    #[argh(positional)]
    addr: String,

    #[argh(positional)]
    target_addr: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

async fn proxy() -> io::Result<()> {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    let client_config = Arc::new(client_config);

    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let server_addr = options.target_addr;

    let certs = load_certs(&options.cert)?;
    let mut keys = load_keys(&options.key)?;

    println!("NUMBER OF CERTS: {}", certs.len());
    println!("NUMBER OF KEYS: {}", keys.len());

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (client_stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let config = Arc::clone(&client_config);
        let srv = server_addr.clone();
        let mut c2s_logger = stdout();
        let mut s2c_logger = stdout();
        tokio::spawn(async move {
            let client = acceptor.accept(client_stream).await.unwrap();
            let (mut client_reader, mut client_writer) = split(client);

            let server_stream = get_server_stream(&srv, config).await.unwrap();
            let (mut server_reader, mut server_writer) = split(server_stream);

            let c2s = async {
                let mut buf: [u8; 8192] = [0; 8192];
                let mut bytes_read: usize;
                loop {
                    match client_reader.read(&mut buf).await {
                        Err(_) => {
                            _ = c2s_logger.write(b"\n\nClient connection closed\n\n").await;
                            _ = c2s_logger.flush().await;
                            _ = server_writer.shutdown().await;
                            return;
                        }
                        Ok(n) => bytes_read = n,
                    }

                    if bytes_read == 0 {
                        continue;
                    }
                    _ = c2s_logger.write(&buf[..bytes_read]).await;
                    _ = c2s_logger.flush().await;

                    match server_writer.write(&buf[..bytes_read]).await {
                        Err(_) => {
                            _ = c2s_logger.write(b"\n\nServer connection closed\n\n").await;
                            _ = c2s_logger.flush().await;
                            _ = server_writer.shutdown().await;
                            return;
                        }
                        Ok(_) => {}
                    }
                }
            };
            let s2c = async {
                let mut buf: [u8; 8192] = [0; 8192];
                let mut bytes_read: usize;
                loop {
                    match server_reader.read(&mut buf).await {
                        Err(_) => {
                            _ = s2c_logger.write(b"\n\nServer connection closed\n\n").await;
                            _ = s2c_logger.flush().await;
                            _ = client_writer.shutdown().await;
                            return;
                        }
                        Ok(n) => bytes_read = n,
                    }

                    if bytes_read == 0 {
                        continue;
                    }
                    _ = s2c_logger.write(&buf[..bytes_read]).await;
                    _ = s2c_logger.flush().await;

                    match client_writer.write(&buf[..bytes_read]).await {
                        Err(_) => {
                            _ = s2c_logger.write(b"\n\nClient connection closed\n\n").await;
                            _ = s2c_logger.flush().await;
                            _ = client_writer.shutdown().await;
                            return;
                        }
                        Ok(_) => {}
                    }
                }
            };

            tokio::select! {
                    _ = c2s => println!("c2s done"),
                    _ = s2c => println!("s2c done"),
            }
        });
    }
}

async fn get_server_stream(
    srv: &str,
    config: Arc<ClientConfig>,
) -> Result<TlsStream<TcpStream>, anyhow::Error> {
    let connector = TlsConnector::from(config);
    let dnsname = ServerName::try_from(srv)?;
    let server = TcpStream::connect(srv).await?;
    let server = connector.connect(dnsname, server).await?;
    Ok(server)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    proxy().await?;
    Ok(())
}
