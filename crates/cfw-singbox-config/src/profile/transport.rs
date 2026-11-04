//! V2Ray transports of a remote outbound and their defaults.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum V2RayTransport {
    Http {
        #[serde(skip_serializing_if = "Option::is_none")]
        method: Option<V2RayHttpMethod>,
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        host: Vec<String>,
    },
    #[serde(rename = "ws")]
    Websocket {
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        headers: Option<WebsocketHeaders>,
    },
    Grpc {
        service_name: String,
    },
    Quic,
    HttpUpgrade {
        #[serde(default = "default_websocket_path")]
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum V2RayHttpMethod {
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "HEAD")]
    Head,
    #[serde(rename = "OPTIONS")]
    Options,
}

impl V2RayHttpMethod {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Head => "HEAD",
            Self::Options => "OPTIONS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WebsocketHeaders {
    #[serde(rename = "Host")]
    pub(crate) host: String,
}

fn default_websocket_path() -> String {
    "/".to_owned()
}
