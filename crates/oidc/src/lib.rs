#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
use axum::{
    Extension,
    extract::Query,
    response::{IntoResponse, Redirect, Response},
    http::HeaderMap,
};
use axum_extra::TypedHeader;
pub use config::OidcConfig;
use config::UserIdClaim;
use error::OidcError;
use headers::Host;
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, TokenResponse, UserInfoClaims,
    core::{CoreClient, CoreGenderClaim, CoreProviderMetadata, CoreResponseType},
};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, Serialize};
use tower_sessions::Session;
pub use user_store::UserStore;

mod config;
mod error;
mod user_store;

const SESSION_KEY_OIDC_STATE: &str = "oauth_state";

#[derive(Debug, Clone)]
pub struct OidcServiceConfig {
    pub default_redirect_path: &'static str,
    pub session_key_user_id: &'static str,
}

#[derive(Debug, Deserialize, Serialize)]
struct OidcState {
    state: CsrfToken,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    redirect_uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserSessionData {
    pub user_id: Option<String>,
    pub email: Option<String>,
    pub user_agent: Option<String>,
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

/// Endpoint that redirects to the authorize endpoint of the OIDC service
pub async fn route_post_oidc(
    Extension(oidc_config): Extension<OidcConfig>,
    session: Session,
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

    session
        .insert(
            SESSION_KEY_OIDC_STATE,
            OidcState {
                state: csrf_token,
                nonce,
                pkce_verifier,
                redirect_uri: Some(String::from("/")),
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
    session: Session,
    Query(AuthCallbackQuery { code, iss, state }): Query<AuthCallbackQuery>,
    Host(host): Host,
    headers: HeaderMap,
) -> Result<Response, OidcError> {
    let callback_uri = format!("https://{host}/frontend/login/oidc/callback");

    if let Some(iss) = iss {
        if iss != oidc_config.issuer {
            return Err(OidcError::Other("Invalid issuer OIDC"));
        }
    }
    let oidc_state = session
        .remove::<OidcState>(SESSION_KEY_OIDC_STATE)
        .await?
        .ok_or(OidcError::Other("Missing OIDC state"))?;

    if oidc_state.state.secret() != &state {
        return Err(OidcError::Other("Invalid OIDC state"));
    }

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
        .map_err(|_| OidcError::Other("Error requesting token OIDC"))?;

    let id_token = token_response
        .id_token()
        .ok_or(OidcError::Other("Missing id token OIDC"))?;

    let id_claims = id_token
        .claims(&oidc_client.id_token_verifier(), &oidc_state.nonce)
        .map_err(|e| OidcError::OidcClaimsVerificationError(e))?;

    if !id_claims
        .audiences()
        .iter()
        .any(|a| a.as_str() == oidc_config.client_id.as_str()) {
        return Err(OidcError::Other("Invalid OIDC client id"));
    }

    if let Some(azp) = id_claims.authorized_party() {
        if azp != &oidc_config.client_id {
            return Err(OidcError::Other("Invalid OIDC client id"));
        }
    }

    let user_info: UserInfoClaims<GroupAdditionalClaims, CoreGenderClaim> = oidc_client
        .user_info(
            token_response.access_token().clone(),
            Some(id_claims.subject().clone()),
        )?
        .request_async(&http_client)
        .await
        .map_err(|e| OidcError::UserInfo(e.to_string()))?;

    if let Some(required_group) = &oidc_config.require_group {
        let has_group = user_info
            .additional_claims()
            .groups
            .as_ref()
            .map(|groups| groups.contains(required_group))
            .unwrap_or(false);

        if !has_group {
            return Ok((
                StatusCode::FORBIDDEN,
                "Access denied: user not in required group",
            )
                .into_response());
        }
    }

    let user_id = match oidc_config.claim_userid {
        UserIdClaim::Sub => user_info.subject().to_string(),
        UserIdClaim::PreferredUsername => user_info
            .preferred_username()
            .ok_or(OidcError::Other("Missing preferred_username claim OIDC"))?
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

    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let email = user_info
        .email()
        .ok_or(OidcError::Other("Missing email claim"))?;
    let session_data = UserSessionData {
        user_id: Some(user_id.to_string()),
        email: Some(email.to_string()),
        user_agent,
    };
    let data_user = serde_json::to_string(&session_data)
            .map_err(|_| OidcError::Other("Failed to serialize user session data"))?;
    session
        .insert(service_config.session_key_user_id, data_user)
        .await?;

    let base_url = Url::parse(&format!("https://{host}"))
        .map_err(|_| OidcError::Other("Invalid host"))?;

    let redirect_to = oidc_state
        .redirect_uri
        .as_deref()
        .and_then(|path| base_url.join(path).ok())
        .filter(|url| url.origin() == base_url.origin()) 
        .map(|url| url.to_string())
        .unwrap_or_else(|| {
            base_url
                .join(&service_config.default_redirect_path)
                .unwrap_or(base_url)
                .to_string()
        });

    Ok(Redirect::to(&redirect_to).into_response())
}
