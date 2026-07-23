//! KMS/HSM production signer adapter.
//!
//! The client contract exposes only managed-key operations. No private-key
//! bytes can be requested, returned, persisted, or logged through this adapter.

use async_trait::async_trait;
use piteka_application::{
    KeyPurpose, KeyStatus, ManagedKeyId, ManagedSignature, ProductionSigner, SigningError,
};

/// Provider response containing only public metadata and signature bytes.
pub struct ManagedSignResponse {
    /// Exact provider key version used.
    pub key_id: ManagedKeyId,
    /// Stable algorithm.
    pub algorithm: String,
    /// Signature.
    pub signature: Vec<u8>,
}

/// Narrow provider SDK boundary implemented by AWS KMS, GCP KMS, Vault, or HSM clients.
#[async_trait]
pub trait ManagedSigningClient: Send + Sync {
    /// Gets lifecycle state from the authoritative key registry.
    async fn status(&self, key_id: &ManagedKeyId) -> Result<KeyStatus, SigningError>;

    /// Signs a digest with provider-side key material.
    async fn sign(
        &self,
        key_id: &ManagedKeyId,
        purpose: KeyPurpose,
        digest: [u8; 32],
    ) -> Result<ManagedSignResponse, SigningError>;
}

/// Production signer backed by an external managed signing client.
pub struct KmsSigner<C> {
    client: C,
}

impl<C> KmsSigner<C> {
    /// Wraps a provider SDK client.
    pub const fn new(client: C) -> Self {
        Self { client }
    }
}

#[async_trait]
impl<C: ManagedSigningClient> ProductionSigner for KmsSigner<C> {
    async fn key_status(&self, key_id: &ManagedKeyId) -> Result<KeyStatus, SigningError> {
        self.client.status(key_id).await
    }

    async fn sign_digest(
        &self,
        key_id: &ManagedKeyId,
        purpose: KeyPurpose,
        digest: [u8; 32],
        now_unix_seconds: u64,
    ) -> Result<ManagedSignature, SigningError> {
        if self.client.status(key_id).await? != KeyStatus::Active {
            return Err(SigningError::KeyNotActive);
        }
        let response = self.client.sign(key_id, purpose, digest).await?;
        if response.key_id != *key_id
            || response.algorithm.trim().is_empty()
            || response.signature.is_empty()
        {
            return Err(SigningError::InvalidResponse);
        }
        Ok(ManagedSignature {
            key_id: response.key_id,
            algorithm: response.algorithm,
            signature: response.signature,
            signed_at_unix_seconds: now_unix_seconds,
        })
    }
}

/// Whether a historic signature remains acceptable under a key lifecycle event.
pub fn signature_within_key_lifecycle(signature: &ManagedSignature, status: KeyStatus) -> bool {
    match status {
        KeyStatus::Active | KeyStatus::VerifyOnly => true,
        KeyStatus::Compromised {
            not_after_unix_seconds,
        } => signature.signed_at_unix_seconds <= not_after_unix_seconds,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Client(KeyStatus);
    #[async_trait]
    impl ManagedSigningClient for Client {
        async fn status(&self, _: &ManagedKeyId) -> Result<KeyStatus, SigningError> {
            Ok(self.0)
        }
        async fn sign(
            &self,
            key_id: &ManagedKeyId,
            _: KeyPurpose,
            _: [u8; 32],
        ) -> Result<ManagedSignResponse, SigningError> {
            Ok(ManagedSignResponse {
                key_id: key_id.clone(),
                algorithm: "Ed25519".into(),
                signature: vec![1; 64],
            })
        }
    }

    #[tokio::test]
    async fn rotation_key_cannot_sign_but_old_signatures_remain_verifiable() {
        let key = ManagedKeyId::parse("kms://mandates/v1").unwrap();
        let signer = KmsSigner::new(Client(KeyStatus::VerifyOnly));
        assert_eq!(
            signer
                .sign_digest(&key, KeyPurpose::Mandate, [1; 32], 100)
                .await,
            Err(SigningError::KeyNotActive)
        );
        let historic = ManagedSignature {
            key_id: key,
            algorithm: "Ed25519".into(),
            signature: vec![1],
            signed_at_unix_seconds: 90,
        };
        assert!(signature_within_key_lifecycle(
            &historic,
            KeyStatus::Compromised {
                not_after_unix_seconds: 95
            }
        ));
        assert!(!signature_within_key_lifecycle(
            &historic,
            KeyStatus::Compromised {
                not_after_unix_seconds: 80
            }
        ));
    }
}
