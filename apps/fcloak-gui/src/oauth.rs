use std::{
    env,
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

use keyring::Entry;
use oauth2::reqwest::http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
    basic::BasicClient,
};
use open;
use url::Url;

const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

const DRIVE_SCOPE: &str = "https://www.googleapis.com/auth/drive.file";

const KEYRING_SERVICE: &str = "FCLOAK";
const KEYRING_ACCOUNT: &str = "google-refresh-token-v2";

#[derive(Debug, Clone)]
pub struct GoogleTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub struct GoogleAuth {
    client_id: String,
    client_secret: Option<String>,

    access_token: Option<String>,
    refresh_token: Option<String>,

    expires_at: Option<Instant>,
}

impl GoogleAuth {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let client_id = option_env!("FCLOAK_GOOGLE_CLIENT_ID")
    .ok_or("Google Client ID was not embedded into this build")?
    .to_string();

let client_secret = option_env!("FCLOAK_GOOGLE_CLIENT_SECRET")
    .map(str::to_string);

        Ok(Self {
            client_id,
            client_secret,

            access_token: None,
            refresh_token: None,

            expires_at: None,
        })
    }

    fn keyring_entry() -> Result<Entry, Box<dyn std::error::Error>> {
        Ok(Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)?)
    }

    fn save_refresh_token(token: &str) -> Result<(), Box<dyn std::error::Error>> {
        let entry = Self::keyring_entry()?;

        entry.set_password(token)?;

        Ok(())
    }

    fn load_refresh_token() -> Result<Option<String>, Box<dyn std::error::Error>> {
        let entry = Self::keyring_entry()?;

        match entry.get_password() {
            Ok(token) if !token.trim().is_empty() => Ok(Some(token)),

            Ok(_) => Ok(None),

            Err(_) => Ok(None),
        }
    }

    fn delete_refresh_token() -> Result<(), Box<dyn std::error::Error>> {
        let entry = Self::keyring_entry()?;

        let _ = entry.delete_credential();

        Ok(())
    }

    fn oauth_client(&self, redirect_uri: &str) -> Result<BasicClient, Box<dyn std::error::Error>> {
        let client = BasicClient::new(
            ClientId::new(self.client_id.clone()),
            self.client_secret.clone().map(ClientSecret::new),
            AuthUrl::new(GOOGLE_AUTH_URL.to_string())?,
            Some(TokenUrl::new(GOOGLE_TOKEN_URL.to_string())?),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_uri.to_string())?);

        Ok(client)
    }

    pub fn has_saved_session(&self) -> bool {
        Self::load_refresh_token().ok().flatten().is_some()
    }

    pub fn is_connected(&self) -> bool {
        self.access_token.is_some() && self.refresh_token.is_some()
    }

    pub fn restore_saved_session(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let refresh_token = match Self::load_refresh_token()? {
            Some(token) => token,
            None => return Ok(false),
        };

        match self.refresh_access_token(&refresh_token) {
            Ok(()) => Ok(true),

            Err(error) => {
                self.access_token = None;
                self.refresh_token = None;
                self.expires_at = None;

                Err(format!("saved Google session could not be refreshed: {error}").into())
            }
        }
    }

    fn refresh_access_token(
        &mut self,
        refresh_token: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let client = self.oauth_client("http://localhost")?;

        let token = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request(http_client)?;

        self.access_token = Some(token.access_token().secret().to_string());

        if let Some(new_refresh_token) = token.refresh_token() {
            let value = new_refresh_token.secret().to_string();

            Self::save_refresh_token(&value)?;

            self.refresh_token = Some(value);
        } else {
            self.refresh_token = Some(refresh_token.to_string());
        }

        let expires_in = token.expires_in().unwrap_or(Duration::from_secs(3600));

        self.expires_at = Some(
            Instant::now()
                + expires_in
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or(Duration::from_secs(30)),
        );

        Ok(())
    }

    pub fn access_token(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let needs_refresh = match self.expires_at {
            Some(expires_at) => Instant::now() >= expires_at,

            None => true,
        };

        if needs_refresh {
            let refresh_token = self
                .refresh_token
                .clone()
                .ok_or("Google Drive is not connected")?;

            self.refresh_access_token(&refresh_token)?;
        }

        self.access_token
            .clone()
            .ok_or_else(|| "Google Drive access token unavailable".into())
    }

    pub fn connect_interactive(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;

        let port = listener.local_addr()?.port();

        let redirect_uri = format!("http://127.0.0.1:{}/oauth2callback", port);

        let client = self.oauth_client(&redirect_uri)?;

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        /*
         * oauth2 4.4.2 does not have set_access_type().
         *
         * Google accepts additional authorization
         * parameters, so add access_type and prompt
         * explicitly.
         */
        let (authorize_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(DRIVE_SCOPE.to_string()))
            .add_extra_param("access_type", "offline")
            .add_extra_param("prompt", "consent")
            .set_pkce_challenge(pkce_challenge)
            .url();

        open::that(authorize_url.as_str())?;

        let (mut stream, _) = listener.accept()?;

        let mut request = Vec::new();

        stream.read_to_end(&mut request)?;

        let request_text = String::from_utf8_lossy(&request);

        let request_line = request_text
            .lines()
            .next()
            .ok_or("invalid OAuth callback request")?;

        let path = request_line
            .split_whitespace()
            .nth(1)
            .ok_or("invalid OAuth callback path")?;

        let callback_url = Url::parse(&format!("http://localhost{}", path))?;

        let mut returned_state = None;
        let mut code = None;
        let mut oauth_error = None;

        for (key, value) in callback_url.query_pairs() {
            match key.as_ref() {
                "state" => {
                    returned_state = Some(value.into_owned());
                }

                "code" => {
                    code = Some(value.into_owned());
                }

                "error" => {
                    oauth_error = Some(value.into_owned());
                }

                _ => {}
            }
        }

        if let Some(error) = oauth_error {
            let body = format!(
                r#"<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>FCLOAK - Google Drive Error</title>
<style>
body {{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#0f1419;
    color:#e8edf2;
    font-family:Arial,sans-serif;
}}
.card {{
    width:min(440px,calc(100% - 32px));
    padding:38px;
    text-align:center;
    border-radius:18px;
    background:#171d23;
    border:1px solid #303942;
}}
h1 {{ font-size:23px; }}
p {{ color:#9da8b3; line-height:1.6; }}
button {{
    margin-top:20px;
    padding:11px 22px;
    border:0;
    border-radius:9px;
    background:#e36b6b;
    color:white;
    font-weight:bold;
    cursor:pointer;
}}
</style>
</head>
<body>
<div class="card">
<h1>Google Drive connection failed</h1>
<p>{}</p>
<button onclick="window.close()">Close Window</button>
</div>
</body>
</html>"#,
                error
            );

            let response = format!(
                "HTTP/1.1 400 Bad Request\r\n\
                 Content-Type: text/html; charset=utf-8\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );

            let _ = stream.write_all(response.as_bytes());

            return Err(format!("Google OAuth failed: {}", error).into());
        }

        let returned_state = returned_state.ok_or("OAuth callback did not contain state")?;

        if returned_state != csrf_token.secret().as_str() {
            return Err("OAuth state validation failed".into());
        }

        let code = code.ok_or("OAuth callback did not contain authorization code")?;

        let body = r#"<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>FCLOAK - Google Drive Connected</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #0f1419;
            color: #e8edf2;
            font-family: Arial, sans-serif;
        }
        .card {
            width: min(440px, calc(100% - 32px));
            padding: 38px;
            text-align: center;
            border-radius: 18px;
            background: #171d23;
            border: 1px solid #303942;
            box-shadow: 0 20px 60px rgba(0,0,0,.35);
        }
        .check {
            width: 64px;
            height: 64px;
            margin: 0 auto 20px;
            border-radius: 50%;
            background: #193d2a;
            color: #55d98a;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            font-weight: bold;
        }
        h1 {
            margin: 0 0 12px;
            font-size: 24px;
        }
        p {
            color: #9da8b3;
            line-height: 1.6;
            margin: 8px 0;
        }
        button {
            margin-top: 22px;
            padding: 11px 22px;
            border: 0;
            border-radius: 9px;
            background: #55d98a;
            color: #07120b;
            font-weight: bold;
            cursor: pointer;
        }
        .hint {
            font-size: 12px;
            margin-top: 16px;
            opacity: .75;
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="check">✓</div>
        <h1>Google Drive Connected</h1>
        <p>FCLOAK is now connected to your Google Drive.</p>
        <p>You can return to the FCLOAK application.</p>
        <button onclick="window.close()">Close Window</button>
        <p class="hint">This page will try to close automatically.</p>
    </div>

    <script>
        window.addEventListener("load", function () {
            setTimeout(function () {
                window.close();
            }, 1200);
        });
    </script>
</body>
</html>"#;

        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: text/html; charset=utf-8\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{}",
            body.len(),
            body
        );

        let _ = stream.write_all(response.as_bytes());

        let token = client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.secret().to_string()))
            .request(http_client)?;

        let access_token = token.access_token().secret().to_string();

        let refresh_token = token
            .refresh_token()
            .map(|token| token.secret().to_string())
            .ok_or(
                "Google did not return a refresh token. \
                     Disconnect FCLOAK from Google and connect again.",
            )?;

        Self::save_refresh_token(&refresh_token)?;

        self.access_token = Some(access_token);

        self.refresh_token = Some(refresh_token);

        let expires_in = token.expires_in().unwrap_or(Duration::from_secs(3600));

        self.expires_at = Some(
            Instant::now()
                + expires_in
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or(Duration::from_secs(30)),
        );

        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Self::delete_refresh_token()?;

        self.access_token = None;
        self.refresh_token = None;
        self.expires_at = None;

        Ok(())
    }
}
