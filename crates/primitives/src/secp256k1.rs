//! secp256k1 wrapper

pub use secp256k1::*;

#[cfg(not(feature = "secp256k1"))]
#[allow(clippy::module_inception)]
mod secp256k1 {
    use crate::keccak256;
    use crate::B256;
    use k256::ecdsa::{Error, RecoveryId, Signature, VerifyingKey};

    pub fn ecrecover(sig: &[u8; 65], msg: &B256) -> Result<B256, Error> {
        // parse signature
        let recid = RecoveryId::from_byte(sig[64]).expect("Recovery id is valid");
        let signature = Signature::from_slice(&sig[..64])?;

        // recover key
        let recovered_key = VerifyingKey::recover_from_prehash(&msg[..], &signature, recid)?;

        // hash it
        let mut hash = keccak256(
            &recovered_key
                .to_encoded_point(/* compress = */ false)
                .as_bytes()[1..],
        );

        // truncate to 20 bytes
        hash[..12].fill(0);
        Ok(hash)
    }
}

#[cfg(feature = "secp256k1")]
#[allow(clippy::module_inception)]
mod secp256k1 {
    use crate::keccak256;
    use crate::B256;
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, Secp256k1,
    };

    // Silence the unused crate dependency warning.
    use k256 as _;

    pub fn ecrecover(sig: &[u8; 65], msg: &B256) -> Result<B256, secp256k1::Error> {
        let sig =
            RecoverableSignature::from_compact(&sig[0..64], RecoveryId::from_i32(sig[64] as i32)?)?;

        let secp = Secp256k1::new();
        let public = secp.recover_ecdsa(&Message::from_digest_slice(&msg[..])?, &sig)?;

        let mut hash = keccak256(&public.serialize_uncompressed()[1..]);
        hash[..12].fill(0);
        Ok(hash)
    }
}
