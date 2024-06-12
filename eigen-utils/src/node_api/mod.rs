use http_body_util::Full;
use hyper::{
    body::{self, Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};

use serde::Serialize;
use serde_json::json;
use std::{convert::Infallible, sync::Arc};
use tokio::net::TcpListener;

use self::tokiort::TokioIo;

pub mod tokiort;

const BASE_URL: &str = "/eigen";
const SPEC_SEM_VER: &str = "v0.0.1";

#[derive(Debug, Clone, Copy)]
enum NodeHealth {
    Healthy,
    PartiallyHealthy,
    Unhealthy,
}

#[derive(Debug, Serialize, Clone, Copy)]
enum ServiceStatus {
    Up,
    Down,
    Initializing,
}

#[derive(Debug, Serialize, Clone)]
pub struct NodeService {
    id: String,
    name: String,
    description: String,
    status: ServiceStatus,
}

#[derive(Clone)]
pub struct NodeApi {
    avs_node_name: String,
    avs_node_sem_ver: String,
    health: NodeHealth,
    node_services: Vec<NodeService>,
    ip_port_address: String,
}

impl NodeApi {
    pub fn new(avs_node_name: &str, avs_node_sem_ver: &str, ip_port_addr: &str) -> Self {
        Self {
            avs_node_name: avs_node_name.to_string(),
            avs_node_sem_ver: avs_node_sem_ver.to_string(),
            health: NodeHealth::Healthy,
            node_services: Vec::new(),
            ip_port_address: ip_port_addr.to_string(),
        }
    }

    fn update_health(&mut self, health: NodeHealth) {
        self.health = health;
    }

    fn register_new_service(&mut self, service: NodeService) {
        self.node_services.push(service);
    }

    fn update_service_status(
        &mut self,
        service_id: &str,
        service_status: ServiceStatus,
    ) -> Result<(), String> {
        for service in self.node_services.iter_mut() {
            if service.id == service_id {
                service.status = service_status;
                return Ok(());
            }
        }
        Err(format!("Service with serviceId {} not found", service_id))
    }

    fn deregister_service(&mut self, service_id: &str) -> Result<(), String> {
        if let Some(index) = self
            .node_services
            .iter()
            .position(|service| service.id == service_id)
        {
            self.node_services.remove(index);
            return Ok(());
        }
        Err(format!("Service with serviceId {} not found", service_id))
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(&self.ip_port_address).await?;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let io = TokioIo::new(stream);
            let this = Arc::new(self.clone());
            tokio::task::spawn(async move {
                if let Err(err) = http1::Builder::new()
                    .serve_connection(
                        io,
                        service_fn(move |req| {
                            let this = Arc::clone(&this);
                            async move { this.router(req).await }
                        }),
                    )
                    .await
                {
                    println!("Error serving connection: {:?}", err);
                }
            });
        }
    }

    async fn router(
        &self,
        req: Request<body::Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, path) if path == format!("{}/node", BASE_URL) => {
                self.node_handler().await
            }
            (&Method::GET, path) if path == format!("{}/node/health", BASE_URL) => {
                self.health_handler().await
            }
            (&Method::GET, path) if path == format!("{}/node/services", BASE_URL) => {
                self.services_handler().await
            }
            (&Method::GET, path) if path.starts_with(&format!("{}/node/services/", BASE_URL)) => {
                self.service_health_handler(req).await
            }
            _ => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::from("Not Found")))
                .unwrap()),
        }
    }

    async fn node_handler(&self) -> Result<Response<Full<Bytes>>, Infallible> {
        let response = json!({
            "node_name": self.avs_node_name,
            "spec_version": SPEC_SEM_VER,
            "node_version": self.avs_node_sem_ver,
        });

        Ok(json_response(response))
    }

    async fn health_handler(&self) -> Result<Response<Full<Bytes>>, Infallible> {
        match self.health {
            NodeHealth::Healthy => Ok(Response::new(Full::new(Bytes::from("")))),
            NodeHealth::PartiallyHealthy => Ok(Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .body(Full::new(Bytes::from("")))
                .unwrap()),
            NodeHealth::Unhealthy => Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Full::new(Bytes::from("")))
                .unwrap()),
        }
    }

    async fn services_handler(&self) -> Result<Response<Full<Bytes>>, Infallible> {
        let response = json!({
            "services": self.node_services,
        });

        Ok(json_response(response))
    }

    async fn service_health_handler(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let path = req.uri().path();
        let service_id = path
            .trim_start_matches(&format!("{}/node/services/", BASE_URL))
            .trim_end_matches("/health");

        for service in self.node_services.iter() {
            if service.id == service_id {
                return match service.status {
                    ServiceStatus::Up => Ok(Response::new(Full::new(Bytes::from("")))),
                    ServiceStatus::Down => Ok(Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .body(Full::new(Bytes::from("")))
                        .unwrap()),
                    ServiceStatus::Initializing => Ok(Response::builder()
                        .status(StatusCode::PARTIAL_CONTENT)
                        .body(Full::new(Bytes::from("")))
                        .unwrap()),
                };
            }
        }

        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("")))
            .unwrap())
    }
}

fn json_response<T: Serialize>(data: T) -> Response<Full<Bytes>> {
    let body = serde_json::to_string(&data).unwrap();
    Response::builder()
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
