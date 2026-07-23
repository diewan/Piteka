//! Stable API error types.
//!
//! Every error follows the same JSON shape so that clients can parse failures
//! uniformly. No internal details leak into the response body.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

/// A single cause within an error response.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorCause {
    /// Machine-readable error code.
    pub code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Optional field or header that triggered the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// The top-level error envelope returned by every endpoint.
///
/// ```json
/// {
///   "error": {
///     "code": "NOT_FOUND",
///     "message": "action request `req-1` not found",
///     "causes": [
///       { "code": "NOT_FOUND", "message": "action request `req-1` not found" }
///     ]
///   }
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorDetail,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub causes: Option<Vec<ErrorCause>>,
}

/// All API-level errors.
#[derive(Debug)]
pub enum ApiError {
    /// The requested resource was not found.
    NotFound { resource: String, id: String },
    /// The request body was malformed or missing required fields.
    BadRequest { causes: Vec<ErrorCause> },
    /// The request failed authentication (e.g., invalid webhook signature).
    Unauthorized { code: String, message: String },
    /// The idempotency key is already in use.
    IdempotencyConflict { idempotency_key: String },
    /// The action request is in a state that does not allow the requested operation.
    InvalidState { current: String, attempted: String },
    /// Optimistic concurrency conflict (CAS failed).
    Conflict {
        expected_version: i64,
        current_version: i64,
    },
    /// The caller lacks the required capability.
    Forbidden { capability: String },
    /// A server-side failure (storage, etc.).
    Internal(String),
}

impl ApiError {
    /// Returns a 404 Not Found response.
    pub fn not_found(resource: impl Into<String>, id: impl Into<String>) -> Self {
        Self::NotFound {
            resource: resource.into(),
            id: id.into(),
        }
    }

    /// Returns a 400 Bad Request response for a single cause.
    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::BadRequest {
            causes: vec![ErrorCause {
                code: code.into(),
                message: message.into(),
                source: None,
            }],
        }
    }

    /// Returns a 400 Bad Request response for a missing required header.
    pub fn missing_required_header(header: &str) -> Json<ErrorResponse> {
        Json(ErrorResponse {
            error: ErrorDetail {
                code: "MISSING_REQUIRED_HEADER".to_string(),
                message: format!("The `{}` header is required", header),
                causes: Some(vec![ErrorCause {
                    code: "MISSING_REQUIRED_HEADER".to_string(),
                    message: format!("The `{}` header must be present", header),
                    source: Some(header.to_string()),
                }]),
            },
        })
    }

    /// Returns a 401 Unauthorized response for authentication failures.
    pub fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Unauthorized {
            code: code.into(),
            message: message.into(),
        }
    }

    /// Returns a 500 Internal Server Error response.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    /// Returns a 409 Conflict response for a CAS conflict.
    pub fn conflict(expected: i64, current: i64) -> Self {
        Self::Conflict {
            expected_version: expected,
            current_version: current,
        }
    }
}

impl From<piteka_storage::StorageError> for ApiError {
    fn from(err: piteka_storage::StorageError) -> Self {
        match err {
            piteka_storage::StorageError::InvalidTenantScope => {
                Self::bad_request("INVALID_TENANT_SCOPE", "The tenant scope is invalid")
            }
            piteka_storage::StorageError::ImmutableViolation { .. } => {
                Self::Internal("immutable violation".to_string())
            }
            piteka_storage::StorageError::EvidenceDigestMismatch { .. } => {
                Self::Internal("evidence digest mismatch".to_string())
            }
            piteka_storage::StorageError::EmptyField(field) => Self::bad_request(
                "EMPTY_FIELD",
                format!("Required field `{}` is empty", field),
            ),
            piteka_storage::StorageError::Backend(msg) => Self::Internal(msg),
        }
    }
}

impl From<piteka_application::ActionRequestUseCaseError> for ApiError {
    fn from(err: piteka_application::ActionRequestUseCaseError) -> Self {
        match err {
            piteka_application::ActionRequestUseCaseError::Storage(storage) => Self::from(storage),
            piteka_application::ActionRequestUseCaseError::NotFound(id) => {
                Self::not_found("action request", id)
            }
            piteka_application::ActionRequestUseCaseError::InvalidTransition {
                current,
                attempted,
            } => Self::InvalidState {
                current: format!("{:?}", current),
                attempted: attempted.to_string(),
            },
            piteka_application::ActionRequestUseCaseError::Conflict {
                expected_version,
                current_version,
            } => Self::Conflict {
                expected_version,
                current_version,
            },
            piteka_application::ActionRequestUseCaseError::IntentMismatch {
                expected,
                submitted,
            } => Self::bad_request(
                "INTENT_MISMATCH",
                format!(
                    "Approval was bound to a different intent: expected {expected}, submitted {submitted:?}"
                ),
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, detail) = match &self {
            Self::NotFound { resource, id } => (
                StatusCode::NOT_FOUND,
                ErrorDetail {
                    code: "NOT_FOUND".to_string(),
                    message: format!("{} `{}` not found", resource, id),
                    causes: Some(vec![ErrorCause {
                        code: "NOT_FOUND".to_string(),
                        message: format!("{} `{}` not found", resource, id),
                        source: Some("id".to_string()),
                    }]),
                },
            ),
            Self::BadRequest { causes } => (
                StatusCode::BAD_REQUEST,
                ErrorDetail {
                    code: "BAD_REQUEST".to_string(),
                    message: "The request body is malformed or missing required fields".to_string(),
                    causes: Some(causes.clone()),
                },
            ),
            Self::Unauthorized { code, message } => (
                StatusCode::UNAUTHORIZED,
                ErrorDetail {
                    code: code.clone(),
                    message: message.clone(),
                    causes: Some(vec![ErrorCause {
                        code: code.clone(),
                        message: message.clone(),
                        source: None,
                    }]),
                },
            ),
            Self::IdempotencyConflict { idempotency_key } => (
                StatusCode::CONFLICT,
                ErrorDetail {
                    code: "IDEMPOTENCY_CONFLICT".to_string(),
                    message: format!(
                        "Idempotency key `{}` has already been used",
                        idempotency_key
                    ),
                    causes: Some(vec![ErrorCause {
                        code: "IDEMPOTENCY_CONFLICT".to_string(),
                        message: format!(
                            "Idempotency key `{}` has already been used",
                            idempotency_key
                        ),
                        source: Some("Idempotency-Key".to_string()),
                    }]),
                },
            ),
            Self::InvalidState { current, attempted } => (
                StatusCode::CONFLICT,
                ErrorDetail {
                    code: "INVALID_STATE".to_string(),
                    message: format!(
                        "Cannot {} from status `{}`",
                        attempted, current
                    ),
                    causes: Some(vec![ErrorCause {
                        code: "INVALID_STATE".to_string(),
                        message: format!(
                            "The action request is in status `{}`; expected `Pending` for approve/reject or `Approved` for revoke",
                            current
                        ),
                        source: Some("status".to_string()),
                    }]),
                },
            ),
            Self::Conflict {
                expected_version,
                current_version,
            } => (
                StatusCode::CONFLICT,
                ErrorDetail {
                    code: "CONFLICT".to_string(),
                    message: "Optimistic concurrency conflict".to_string(),
                    causes: Some(vec![
                        ErrorCause {
                            code: "CONFLICT".to_string(),
                            message: format!(
                                "Expected version {}, current version {}",
                                expected_version, current_version
                            ),
                            source: Some("version".to_string()),
                        },
                        ErrorCause {
                            code: "OPTIMISTIC_CONFLICT".to_string(),
                            message: "Another request modified this resource. Retry with the current version.".to_string(),
                            source: None,
                        },
                    ]),
                },
            ),
            Self::Forbidden { capability } => (
                StatusCode::FORBIDDEN,
                ErrorDetail {
                    code: "FORBIDDEN".to_string(),
                    message: format!("The caller lacks capability `{}`", capability),
                    causes: Some(vec![ErrorCause {
                        code: "FORBIDDEN".to_string(),
                        message: format!("Required capability: `{}`", capability),
                        source: Some("capability".to_string()),
                    }]),
                },
            ),
            Self::Internal(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ErrorDetail {
                    code: "INTERNAL_ERROR".to_string(),
                    message: "An internal error occurred".to_string(),
                    causes: Some(vec![ErrorCause {
                        code: "INTERNAL_ERROR".to_string(),
                        message: msg.clone(),
                        source: None,
                    }]),
                },
            ),
        };

        (status, Json(ErrorResponse { error: detail })).into_response()
    }
}
