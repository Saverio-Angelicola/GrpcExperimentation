use crate::proto::experimentation_server::{Experimentation, ExperimentationServer};
use crate::proto::{ExpRequest, ExpResponse};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};
use tower::{Layer, Service};

mod proto {
    tonic::include_proto!("experimentation");
    pub(crate) const FILE_DESCRIPTOR_SET: &[u8] =
        tonic::include_file_descriptor_set!("experimentation_descriptor");
}

#[derive(Debug, Clone)]
struct LoggingMiddleware<S> {
    inner: S,
}

impl<S, Request> Service<Request> for LoggingMiddleware<S>
where
    S: Service<Request>,
    S::Future: Send + 'static,
    Request: std::fmt::Debug,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request) -> Self::Future {
        // Log the incoming request
        tracing::info!(target: "grpc_request", ?request, "Received gRPC request");

        let start = std::time::Instant::now();
        let future = self.inner.call(request);

        Box::pin(async move {
            // Await the response
            let response = future.await?;

            // Log timing information
            let elapsed = start.elapsed();
            tracing::info!(
                target: "grpc_response",
                elapsed_ms = elapsed.as_millis(),
                "Request completed"
            );

            Ok(response)
        })
    }
}

#[derive(Clone, Debug)]
struct LoggingLayer;

impl<S> Layer<S> for LoggingLayer {
    type Service = LoggingMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        LoggingMiddleware { inner: service }
    }
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
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    tracing::info!(message = "Starting server.", %addr);

    let cert = std::fs::read_to_string("tls/domain.crt")?;
    let key = std::fs::read_to_string("tls/decrypted_domain.key")?;

    let client_ca_cert = std::fs::read_to_string("tls/rootCA.crt")?;
    let client_ca_cert = Certificate::from_pem(client_ca_cert);

    let service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1alpha()?;

    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<ExperimentationServer<ExperimentationService>>()
        .await;

    Server::builder()
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .tcp_nodelay(true)
        .concurrency_limit_per_connection(32)
        .timeout(Duration::from_secs(30))
        .tls_config(ServerTlsConfig::new()
            .client_ca_root(client_ca_cert)
            .identity(Identity::from_pem(&cert, &key)))?
        .layer(LoggingLayer)
        .add_service(health_service)
        .add_service(service)
        .add_service(ExperimentationServer::new(ExperimentationService::default()))
        .serve(addr)
        .await?;
    Ok(())
}
