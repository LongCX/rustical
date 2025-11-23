use super::AuthenticationProvider;
use axum::{extract::Request, response::Response};
use futures_core::future::BoxFuture;
use axum_extra::extract::CookieJar;
use headers::{Authorization, HeaderMapExt, authorization::Basic};
use std::{
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};
use tracing::{Instrument, info_span};
use rustical_oidc::RedisSessionStore;

const COOKIE_SESSION_NAME: &str = "rustical-session";

pub struct AuthenticationLayer<AP: AuthenticationProvider> {
    auth_provider: Arc<AP>,
    redis_store: RedisSessionStore,
}

impl<AP: AuthenticationProvider> Clone for AuthenticationLayer<AP> {
    fn clone(&self) -> Self {
        Self {
            auth_provider: self.auth_provider.clone(),
            redis_store: self.redis_store.clone(),
        }
    }
}

impl<AP: AuthenticationProvider> AuthenticationLayer<AP> {
    pub const fn new(auth_provider: Arc<AP>, redis_store: RedisSessionStore) -> Self {
        Self { 
            auth_provider,
            redis_store,
        }
    }
}

impl<S, AP: AuthenticationProvider> Layer<S> for AuthenticationLayer<AP> {
    type Service = AuthenticationMiddleware<S, AP>;

    fn layer(&self, inner: S) -> Self::Service {
        Self::Service {
            inner,
            auth_provider: self.auth_provider.clone(),
            redis_store: self.redis_store.clone(),
        }
    }
}

pub struct AuthenticationMiddleware<S, AP: AuthenticationProvider> {
    inner: S,
    auth_provider: Arc<AP>,
    redis_store: RedisSessionStore,
}

impl<S: Clone, AP: AuthenticationProvider> Clone for AuthenticationMiddleware<S, AP> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            auth_provider: self.auth_provider.clone(),
            redis_store: self.redis_store.clone(),
        }
    }
}

impl<S, AP: AuthenticationProvider> Service<Request> for AuthenticationMiddleware<S, AP>
where
    S: Service<Request, Response = Response> + Send + Clone + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request) -> Self::Future {
        let auth_header: Option<Authorization<Basic>> = request.headers().typed_get();
        let ap = self.auth_provider.clone();
        let redis_store = self.redis_store.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if let Some(cookie_jar) = request.extensions().get::<CookieJar>() {
                if let Some(session_cookie) = cookie_jar.get(COOKIE_SESSION_NAME) {
                    let session_id = session_cookie.value();
                    
                    // Get user session data from Redis
                    if let Ok(Some(session_data)) = redis_store.get_user_session(session_id).await {
                        if let Ok(Some(user)) = ap.get_principal(&session_data.user_id).await {
                            request.extensions_mut().insert(user);
                        }
                    }
                }
            }

            if let Some(auth) = auth_header {
                let user_id = auth.username();
                let password = auth.password();
                if let Ok(Some(user)) = ap
                    .validate_app_token(user_id, password)
                    .instrument(info_span!("validate_user_token"))
                    .await
                {
                    request.extensions_mut().insert(user);
                }
            }

            let response = inner.call(request).await?;
            Ok(response)
        })
    }
}
