use anyhow::{Context, bail};
use serde::Serialize;

#[derive(Clone)]
pub struct ResendMailer {
    http: reqwest::Client,
    api_key: String,
    from: String,
}

#[derive(Serialize)]
struct ResendRequest<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    html: &'a str,
}

impl ResendMailer {
    pub fn new(api_key: String, from: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_key,
            from,
        }
    }

    pub async fn send_html(&self, to: &str, subject: &str, html: &str) -> anyhow::Result<()> {
        let res = self
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.api_key)
            .json(&ResendRequest {
                from: &self.from,
                to: [to],
                subject,
                html,
            })
            .send()
            .await
            .context("Falha de rede ao chamar API do Resend")?;

        if !res.status().is_success() {
            let status = res.status();
            let body = res.text().await.unwrap_or_default();
            bail!("Resend retornou HTTP {status}: {body}");
        }

        Ok(())
    }
}
