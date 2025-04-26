use crate::jwt::{extract_user_id_from_jwt, validate_jwt};
use actix_web::dev::Transform;
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse},
    error::ErrorUnauthorized,
    http::{
        header::{HeaderName, HeaderValue},
        Method,
    },
    Error, HttpMessage,
};
use futures::future::{err, ok, Ready};
use futures::FutureExt;
use std::future::{Future, Ready as StdReady};
use std::pin::Pin;
use std::rc::Rc;
use tracing::info;

pub struct AuthenticationMiddleware<S> {
    service: Rc<S>,
}

impl<S, B> AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    pub fn new(service: Rc<S>) -> Self {
        AuthenticationMiddleware { service }
    }
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Skip authentication for OPTIONS requests
        if *req.method() == Method::OPTIONS {
            return Box::pin(self.service.call(req));
        }

        let auth_header = req.headers().get("Authorization");

        if let Some(auth_header) = auth_header {
            if let Ok(auth_value) = auth_header.to_str() {
                if auth_value.starts_with("Bearer ") {
                    let token = auth_value[7..].trim(); // Remove "Bearer " prefix

                    match validate_jwt(token) {
                        Ok(_) => {
                            match extract_user_id_from_jwt(token) {
                                Ok(user_id) => {
                                    info!("Authenticated user with ID: {}", user_id);
                                    req.extensions_mut().insert(user_id.clone()); // Store user_id in extensions
                                    let fut = self.service.call(req);
                                    return Box::pin(async move {
                                        let res = fut.await?;
                                        Ok(res)
                                    });
                                }
                                Err(e) => {
                                    tracing::error!("Failed to extract user ID: {}", e);
                                    return Box::pin(err(ErrorUnauthorized("Invalid token")));
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("Invalid token: {}", e);
                            return Box::pin(err(ErrorUnauthorized("Invalid token")));
                        }
                    }
                } else {
                    tracing::error!("Invalid authorization format");
                    return Box::pin(err(ErrorUnauthorized("Invalid authorization format")));
                }
            } else {
                tracing::error!("Invalid authorization header value");
                return Box::pin(err(ErrorUnauthorized("Invalid authorization header value")));
            }
        } else {
            tracing::error!("Missing authorization header");
            return Box::pin(err(ErrorUnauthorized("Missing authorization header")));
        }
    }
}

pub struct AuthenticationMiddlewareFactory;

impl AuthenticationMiddlewareFactory {
    pub fn new() -> Self {
        AuthenticationMiddlewareFactory
    }
}

impl<S, B> Transform<S, ServiceRequest> for AuthenticationMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticationMiddleware<S>;
    type Future = std::future::Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        std::future::ready(Ok(AuthenticationMiddleware::new(Rc::new(service))))
    }
}
