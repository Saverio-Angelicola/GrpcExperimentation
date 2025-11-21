use crate::proto::experimentation_server::{Experimentation, ExperimentationServer};
use crate::proto::{ExpRequest, ExpResponse};
use std::net::SocketAddr;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tonic::server::NamedService;

mod proto {
    tonic::include_proto!("experimentation");
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("experimentation_descriptor");
}

#[derive(Debug, Default)]
struct ExperimentationService {}

#[tonic::async_trait]
impl Experimentation for ExperimentationService {
    async fn test(&self, request: Request<ExpRequest>) -> Result<Response<ExpResponse>, Status> {
        match request
            .peer_certs() {
            None => {
                Err(Status::internal("Client did not send its certs!"))
            }
            Some(certs) => {
                println!("Got a request: {:?}", request.get_ref().msg);
                Ok(Response::new(ExpResponse{
                    res: "Hello world".to_string(),
                }))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "[::]:50051".parse()?;

    println!("Server listening on {}", addr);

    let data_dir = std::path::PathBuf::from_iter([std::env!("CARGO_MANIFEST_DIR"), "data"]);
    let cert = std::fs::read_to_string("tls/domain.crt")?;
    let key = std::fs::read_to_string("tls/decrypted_domain.key")?;

    let client_ca_cert = std::fs::read_to_string("tls/rootCA.crt")?;
    let client_ca_cert = Certificate::from_pem(client_ca_cert);

    let service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();

    // Set the serving status of "ExperimentationService"
    health_reporter
        .set_serving::<ExperimentationServer<ExperimentationService>>()
        .await;

    Server::builder()
        .tls_config(ServerTlsConfig::new()
            .client_ca_root(client_ca_cert)
            .identity(Identity::from_pem(&cert, &key)))?
        .add_service(health_service)
        .add_service(service)
        .add_service(ExperimentationServer::new(ExperimentationService::default()))
        .serve(addr)
        .await?;
    Ok(())
}
