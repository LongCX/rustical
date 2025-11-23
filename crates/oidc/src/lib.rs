#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
use axum::{
    Extension,
    extract::Query,
    response::{IntoResponse, Redirect, Response},
    http::HeaderMap,
};
use axum_extra::extract::{Host, cookie::Cookie};
pub use config::OidcConfig;
use config::UserIdClaim;
use error::OidcError;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, TokenResponse, UserInfoClaims,
    core::{CoreClient, CoreGenderClaim, CoreProviderMetadata, CoreResponseType},
};
use redis::AsyncCommands;
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
pub use user_store::UserStore;
use uuid::Uuid;

mod config;
mod error;
mod user_store;

const COOKIE_SESSION_NAME: &str = "rustical-session";
const REDIS_KEY_OIDC_STATE: &str = "oauth_state";
const REDIS_KEY_USER_SESSION: &str = "rustical";

#[derive(Debug, Clone)]
pub struct OidcServiceConfig {
    pub default_redirect_path: &'static str,
    pub session_key_user_id: &'static str,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserSessionData {
    pub user_id: String,
    pub email: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RedisSessionStore {
    client: redis::Client,
}

impl RedisSessionStore {
    pub fn new(redis_url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(redis_url)?;
        Ok(Self { client })
    }

    async fn get_connection(&self) -> Result<redis::aio::MultiplexedConnection, OidcError> {
        self.client
            .get_multiplexed_async_connection()
            .await
            .map_err(|_| OidcError::Other("Failed to connect to Redis"))
    }

    pub async fn set_oidc_state(
        &self,
        state: &OidcState,
    ) -> Result<(), OidcError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", REDIS_KEY_OIDC_STATE, state.state.secret());
        let value = serde_json::to_string(state)
            .map_err(|_| OidcError::Other("Failed to serialize OIDC state"))?;
        
        conn.set_ex::<_, _, ()>(&key, value, 300) // 5 minutes for OIDC state
            .await
            .map_err(|_| OidcError::Other("Failed to store OIDC state"))?;
        
        Ok(())
    }
    
    pub async fn get_oidc_state(&self, state: &str) -> Result<Option<OidcState>, OidcError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", REDIS_KEY_OIDC_STATE, state);
        
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|_| OidcError::Other("Failed to retrieve OIDC state"))?;
        
        match value {
            Some(v) => {
                let state = serde_json::from_str(&v)
                    .map_err(|_| OidcError::Other("Failed to deserialize OIDC state"))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    pub async fn remove_oidc_state(&self, state: &str) -> Result<(), OidcError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", REDIS_KEY_OIDC_STATE, state);
        
        conn.del::<_, ()>(&key)
            .await
            .map_err(|_| OidcError::Other("Failed to delete OIDC state"))?;
        
        Ok(())
    }

    pub async fn set_user_session(
        &self,
        session_id: &str,
        session_data: &UserSessionData,
    ) -> Result<(), OidcError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", REDIS_KEY_USER_SESSION, session_id);
        
        let value = serde_json::to_string(session_data)
            .map_err(|_| OidcError::Other("Failed to serialize user session data"))?;

        conn.set_ex::<_, _, ()>(&key, value, 3600 * 24) // 24 hours for user session
            .await
            .map_err(|_| OidcError::Other("Failed to store user session"))?;
        
        Ok(())
    }

    pub async fn remove_user_session(&self, session_id: &str) -> Result<(), OidcError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", REDIS_KEY_USER_SESSION, session_id);
        
        conn.del::<_, ()>(&key)
            .await
            .map_err(|_| OidcError::Other("Failed to delete user session"))?;
        
        Ok(())
    }

    pub async fn get_user_session(&self, session_id: &str) -> Result<Option<UserSessionData>, OidcError> {
        let mut conn = self.get_connection().await?;
        let key = format!("{}:{}", REDIS_KEY_USER_SESSION, session_id);
        
        let value: Option<String> = conn
            .get(&key)
            .await
            .map_err(|_| OidcError::Other("Failed to retrieve user session"))?;
        
        match value {
            Some(v) => {
                let data: UserSessionData = serde_json::from_str(&v)
                    .map_err(|_| OidcError::Other("Failed to deserialize user session data"))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OidcState {
    state: CsrfToken,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct GroupAdditionalClaims {
    #[serde(default)]
    groups: Option<Vec<String>>,
}

impl openidconnect::AdditionalClaims for GroupAdditionalClaims {}

fn get_http_client() -> reqwest::Client {
    reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Something went wrong :(")
}

async fn get_oidc_client(
    OidcConfig {
        issuer,
        client_id,
        client_secret,
        ..
    }: OidcConfig,
    http_client: &reqwest::Client,
    redirect_uri: RedirectUrl,
) -> Result<
    CoreClient<
        EndpointSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointNotSet,
        EndpointMaybeSet,
        EndpointMaybeSet,
    >,
    OidcError,
> {
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, http_client)
        .await
        .map_err(|err| {
            tracing::error!("An error occured trying to discover OpenID provider: {err}");
            OidcError::Other("Failed to discover OpenID provider")
        })?;

    Ok(CoreClient::from_provider_metadata(
        provider_metadata,
        client_id.clone(),
        client_secret.clone(),
    )
    .set_redirect_uri(redirect_uri))
}

fn create_session_id() -> (String, Option<Cookie<'static>>) {
    let uuid = Uuid::new_v4();
    let session_id = format!("rustical:{}", uuid);
    let cookie = Cookie::build((COOKIE_SESSION_NAME, session_id.clone()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(axum_extra::extract::cookie::SameSite::Strict)
        .max_age(time::Duration::days(1))
        .build();
    (session_id, Some(cookie))
}

/// Endpoint that redirects to the authorize endpoint of the OIDC service
pub async fn route_post_oidc(
    Extension(oidc_config): Extension<OidcConfig>,
    Extension(redis_store): Extension<RedisSessionStore>,
    Host(host): Host,
) -> Result<Response, OidcError> {
    let callback_uri = format!("https://{host}/frontend/login/oidc/callback");

    let http_client = get_http_client();
    let oidc_client = get_oidc_client(
        oidc_config.clone(),
        &http_client,
        RedirectUrl::new(callback_uri)?,
    )
    .await?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = oidc_client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scopes(oidc_config.scopes.clone())
        .set_pkce_challenge(pkce_challenge)
        .url();

    redis_store
        .set_oidc_state(
            &OidcState {
                state: csrf_token,
                nonce,
                pkce_verifier,
                redirect_uri: Some(String::from("/frontend/login/oidc")),
            },
        )
        .await?;

    Ok(Redirect::to(auth_url.as_str()).into_response())
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthCallbackQuery {
    code: AuthorizationCode,
    // RFC 9207
    iss: Option<IssuerUrl>,
    state: String,
}

// Handle callback from IdP page
pub async fn route_get_oidc_callback<US: UserStore + Clone>(
    Extension(oidc_config): Extension<OidcConfig>,
    Extension(user_store): Extension<US>,
    Extension(service_config): Extension<OidcServiceConfig>,
    Extension(redis_store): Extension<RedisSessionStore>,
    headers: HeaderMap,
    Query(AuthCallbackQuery { code, iss, state }): Query<AuthCallbackQuery>,
    Host(host): Host,
) -> Result<Response, OidcError> {
    let callback_uri = format!("https://{host}/frontend/login/oidc/callback");

    if let Some(iss) = iss {
        assert_eq!(iss, oidc_config.issuer);
    }

    let oidc_state = redis_store
        .get_oidc_state(&state)
        .await?
        .ok_or(OidcError::Other("No local OIDC state"))?;

    assert_eq!(oidc_state.state.secret(), &state);

    // Clean up OIDC state after use
    redis_store.remove_oidc_state(&state).await?;

    let http_client = get_http_client();
    let oidc_client = get_oidc_client(
        oidc_config.clone(),
        &http_client,
        RedirectUrl::new(callback_uri)?,
    )
    .await?;

    let token_response = oidc_client
        .exchange_code(code)?
        .set_pkce_verifier(oidc_state.pkce_verifier)
        .request_async(&http_client)
        .await
        .map_err(|_| OidcError::Other("Error requesting token"))?;
    let id_claims = token_response
        .id_token()
        .ok_or(OidcError::Other("OIDC provider did not return an ID token"))?
        .claims(&oidc_client.id_token_verifier(), &oidc_state.nonce)?;

    let user_info_claims: UserInfoClaims<GroupAdditionalClaims, CoreGenderClaim> = oidc_client
        .user_info(
            token_response.access_token().clone(),
            Some(id_claims.subject().clone()),
        )?
        .request_async(&http_client)
        .await
        .map_err(|e| OidcError::UserInfo(e.to_string()))?;

    if let Some(require_group) = &oidc_config.require_group
        && !user_info_claims
            .additional_claims()
            .groups
            .clone()
            .unwrap_or_default()
            .contains(require_group)
    {
        return Ok((
            StatusCode::UNAUTHORIZED,
            "User is not in an authorized group to use RustiCal",
        )
            .into_response());
    }

    let user_id = match oidc_config.claim_userid {
        UserIdClaim::Sub => user_info_claims.subject().to_string(),
        UserIdClaim::PreferredUsername => user_info_claims
            .preferred_username()
            .ok_or(OidcError::Other("Missing preferred_username claim"))?
            .to_string(),
    };

    match user_store.user_exists(&user_id).await {
        Ok(false) => {
            // User does not exist
            if !oidc_config.allow_sign_up {
                return Ok((StatusCode::UNAUTHORIZED, "User signup is disabled").into_response());
            }
            // Create new user
            if let Err(err) = user_store.insert_user(&user_id).await {
                return Ok(err.into_response());
            }
        }
        Ok(true) => {}
        Err(err) => {
            return Ok(err.into_response());
        }
    }

    let default_redirect = service_config.default_redirect_path.to_owned();
    let base_url: Url = format!("https://{host}").parse().unwrap();
    let redirect_uri = if let Some(redirect_uri) = oidc_state.redirect_uri {
        if let Ok(redirect_url) = base_url.join(&redirect_uri) {
            if redirect_url.origin() == base_url.origin() {
                base_url.path().to_owned()
            } else {
                default_redirect
            }
        } else {
            default_redirect
        }
    } else {
        default_redirect
    };

    let email = user_info_claims.email().map(|e| e.to_string());
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let session_data = UserSessionData {
        user_id: user_id.clone(),
        email,
        user_agent,
    };

    let (session_id, cookie) = create_session_id();
    redis_store.set_user_session(&session_id, &session_data).await?;

    let mut response = Redirect::to(redirect_uri.as_str()).into_response();
    
    if let Some(cookie) = cookie {
        response.headers_mut().insert(
            axum::http::header::SET_COOKIE,
            cookie.to_string().parse().unwrap(),
        );
    }

    Ok(response)
}
