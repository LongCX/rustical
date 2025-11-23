use crate::{OidcConfig, pages::DefaultLayoutData};
use askama::Template;
use askama_web::WebTemplate;
use axum::{
    Extension,
    extract::Query,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use tracing::instrument;
use rustical_oidc::RedisSessionStore;

const COOKIE_SESSION_NAME: &str = "rustical-session";

#[derive(Template, WebTemplate)]
#[template(path = "pages/login.html")]
struct LoginPage<'a> {
    redirect_uri: Option<String>,
    oidc_data: Option<OidcProviderData<'a>>,
}

impl DefaultLayoutData for LoginPage<'_> {
    fn get_user(&self) -> Option<&rustical_store::auth::Principal> {
        None
    }
}

struct OidcProviderData<'a> {
    pub name: &'a str,
    pub redirect_url: String,
}

#[derive(Debug, Deserialize)]
pub struct GetLoginQuery {
    redirect_uri: Option<String>,
}

#[instrument(skip(oidc_config))]
pub async fn route_get_login(
    Query(GetLoginQuery { redirect_uri }): Query<GetLoginQuery>,
    Extension(oidc_config): Extension<Option<OidcConfig>>,
) -> Response {
    let oidc_data = oidc_config
        .as_ref()
        .as_ref()
        .map(|oidc_config| OidcProviderData {
            name: &oidc_config.name,
            redirect_url: "/frontend/login/oidc".to_owned(),
        });
    LoginPage {
        redirect_uri,
        oidc_data,
    }
    .into_response()
}

pub async fn route_post_logout(Extension(redis_store): Extension<RedisSessionStore>, jar: CookieJar,) -> Redirect {
    if let Some(session_id) = jar.get(COOKIE_SESSION_NAME) {
        redis_store.remove_user_session(session_id.value()).await.ok();
    }
    Redirect::to("/frontend/login")
}