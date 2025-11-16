use std::net::SocketAddr;
use tonic::{Request, Response, Status};
use tonic::transport::Server;
use crate::proto::experimentation_server::{Experimentation, ExperimentationServer};
use crate::proto::{ExpRequest, ExpResponse};

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
        println!("Got a request: {:?}", request.get_ref().msg);
        Ok(Response::new(ExpResponse{
            res: "Hello world".to_string(),
        }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = "[::]:50051".parse()?;

    let service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    Server::builder()
        .add_service(service)
        .add_service(ExperimentationServer::new(ExperimentationService::default()))
        .serve(addr)
        .await?;
    Ok(())
}
