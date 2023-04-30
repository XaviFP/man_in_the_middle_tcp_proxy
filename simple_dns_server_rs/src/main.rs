use argh::FromArgs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use trust_dns_client::op::{Header, ResponseCode};
use trust_dns_client::rr::{LowerName, Name, RData, Record, RecordType};
use trust_dns_resolver::error::{ResolveError, ResolveErrorKind};
use trust_dns_resolver::lookup::Lookup;
use trust_dns_resolver::name_server::{GenericConnection, GenericConnectionProvider, TokioRuntime};
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    AsyncResolver, IntoName, TokioAsyncResolver,
};
use trust_dns_server::authority::MessageResponseBuilder;
use trust_dns_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use trust_dns_server::ServerFuture;

///
#[derive(FromArgs)]
struct Options {
    /// domain to spoof
    #[argh(positional)]
    domain: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut resolver_config = ResolverConfig::new();

    let ns_udp = NameServerConfig::new(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        Protocol::Udp,
    );
    resolver_config.add_name_server(ns_udp);

    let mut resolver_opts: ResolverOpts = ResolverOpts::default();
    resolver_opts.num_concurrent_reqs = 0;

    let resolver = TokioAsyncResolver::tokio(resolver_config, resolver_opts).unwrap();
    let arc_resolver = Arc::new(resolver);

    let socket = UdpSocket::bind("0.0.0.0:53").await?;
    let local_addr = socket.local_addr()?;
    println!("LOCAL ADDRESS LISTENING TO DNS ON: {}", local_addr);
    let options: Options = argh::from_env();
    let mut server = ServerFuture::new(MyHandler {
        resolver: arc_resolver.clone(),
        domain: options.domain,
    });
    server.register_socket(socket);
    server.block_until_done().await?;

    Ok(())
}

struct MyHandler {
    resolver: Arc<AsyncResolver<GenericConnection, GenericConnectionProvider<TokioRuntime>>>,
    domain: String,
}

#[async_trait::async_trait]
impl RequestHandler for MyHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        let resolver = self.resolver.as_ref().clone();
        let mut records: Vec<Record> = vec![];

        if request.query().name() == &LowerName::from(Name::from_utf8(self.domain.clone()).unwrap())
        {
            let mut record = Record::default();
            record.set_name(Name::from_utf8(self.domain.clone()).unwrap());
            record.set_record_type(RecordType::A);
            record.set_data(Some(RData::A(Ipv4Addr::new(0, 0, 0, 0))));
            let message = builder.build(header, &records, &[], &[], &[]);
            match response_handle.send_response(message).await {
                Ok(ok) => return ok,
                Err(_) => return ResponseInfo::from(Header::new()),
            }
        }

        dbg!(request.query().name());
        dbg!(request.query().query_class());
        dbg!(request.query().query_type());

        let name = request.query().name().into_name().unwrap();

        let lookup_result: Result<Lookup, ResolveError>;

        match request.query().query_type() {
            RecordType::A => lookup_result = resolver.lookup(name, RecordType::A).await,
            RecordType::AAAA => lookup_result = resolver.lookup(name, RecordType::AAAA).await,
            RecordType::TXT => lookup_result = resolver.lookup(name, RecordType::TXT).await,
            RecordType::SRV => lookup_result = resolver.lookup(name, RecordType::SRV).await,
            RecordType::MX => lookup_result = resolver.lookup(name, RecordType::MX).await,
            _ => {
                header.set_response_code(ResponseCode::NotImp);
                lookup_result = Err(ResolveError::from(ResolveErrorKind::Message(
                    "Record type not supported",
                )))
            }
        };

        match lookup_result {
            Ok(ok) => {
                for record in ok.records() {
                    records.push(record.clone())
                }
            }
            // TODO build appropiate response header based on ResolveError
            Err(_) => {}
        }
        let message = builder.build(header, &records, &[], &[], &[]);

        match response_handle.send_response(message).await {
            Ok(ok) => ok,
            Err(_) => ResponseInfo::from(Header::new()),
        }
    }
}
