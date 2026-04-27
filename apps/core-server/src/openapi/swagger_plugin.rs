use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use axum::middleware::Next;
use http_body_util::BodyExt;
use reqwest::Method;

const PERMISSIONS_PLUGIN_SCRIPT: &str = include_str!("permissions-plugin.js");
const TAG_TITLE_PLUGIN_SCRIPT: &str = include_str!("tag-title-plugin.js");

/// Injects the Swagger-UI permission plugin into the served HTML content
pub async fn adapted_swagger_index(
    request: Request<Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let is_swagger_index = request.method() == Method::GET
        && matches!(
            request.uri().path(),
            "/swagger-ui/" | "/swagger-ui/index.html"
        );

    let response = next.run(request).await;

    if is_swagger_index {
        let (parts, body) = response.into_parts();

        let bytes = body.collect().await.ok().unwrap_or_default().to_bytes();
        let body = if let Ok(mut content) = String::from_utf8(bytes.to_vec()) {
            // insert the plugin script at the end of HTML body
            if let Some(pos) = content.rfind("</body>") {
                content.insert_str(
                    pos,
                    &format!(
                        r#"
                            <script>{PERMISSIONS_PLUGIN_SCRIPT}</script>
                            <script>{TAG_TITLE_PLUGIN_SCRIPT}</script>
                        "#
                    ),
                );
            }

            Body::from(content)
        } else {
            Body::from(bytes)
        };

        return Ok(Response::from_parts(parts, body));
    }

    Ok(response)
}
