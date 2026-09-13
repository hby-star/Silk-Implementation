//! Minimal safe boundary for the pinned mldsa-native v2.0.0 ML-DSA-65 backend.
//! Native calls are available only on Linux x86_64 with AVX2 and POPCNT.

use zeroize::Zeroize;

pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SIGNATURE_BYTES: usize = 3309;
const SECRET_KEY_BYTES: usize = 4032;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Unavailable,
    PublicKeyLength,
    SignatureLength,
    ContextLength,
    Backend(i32),
}

pub fn is_available() -> bool {
    #[cfg(silk_mldsa_native)]
    {
        std::is_x86_feature_detected!("avx2") && std::is_x86_feature_detected!("popcnt")
    }
    #[cfg(not(silk_mldsa_native))]
    false
}

#[derive(Clone)]
pub struct SigningKey {
    secret: Box<[u8; SECRET_KEY_BYTES]>,
    public: VerifyingKey,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey").finish_non_exhaustive()
    }
}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.secret.as_mut_slice().zeroize();
    }
}

#[derive(Clone, Debug)]
pub struct VerifyingKey(Box<[u8; PUBLIC_KEY_BYTES]>);

impl SigningKey {
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, Error> {
        if !is_available() {
            return Err(Error::Unavailable);
        }
        let mut key = Self {
            secret: Box::new([0; SECRET_KEY_BYTES]),
            public: VerifyingKey(Box::new([0; PUBLIC_KEY_BYTES])),
        };
        // SAFETY: CPU support is checked above. All three fixed-size buffers
        // have the FIPS 204 lengths, are valid and do not alias one another.
        checked(unsafe {
            ffi::keypair(
                key.public.0.as_mut_ptr(),
                key.secret.as_mut_ptr(),
                seed.as_ptr(),
            )
        })?;
        Ok(key)
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if !is_available() {
            return Err(Error::Unavailable);
        }
        let mut signature = vec![0; SIGNATURE_BYTES];
        // SAFETY: Private key was produced by keypair. Output is disjoint,
        // fixed-size, and the message is readable for exactly message.len().
        checked(unsafe {
            ffi::sign(
                signature.as_mut_ptr(),
                message.as_ptr(),
                message.len(),
                self.secret.as_ptr(),
            )
        })?;
        Ok(signature)
    }
}

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; PUBLIC_KEY_BYTES] =
            bytes.try_into().map_err(|_| Error::PublicKeyLength)?;
        if !is_available() {
            return Err(Error::Unavailable);
        }
        Ok(Self(Box::new(*bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_BYTES] {
        &self.0
    }

    pub fn verify(&self, signature: &[u8], message: &[u8], context: &[u8]) -> Result<(), Error> {
        if signature.len() != SIGNATURE_BYTES {
            return Err(Error::SignatureLength);
        }
        if context.len() > 255 {
            return Err(Error::ContextLength);
        }
        if !is_available() {
            return Err(Error::Unavailable);
        }
        // SAFETY: Public key and signature lengths are checked before calling
        // the upstream API (which has no signature-length argument). Message
        // and context slices are valid for their declared lengths.
        checked(unsafe {
            ffi::verify(
                signature.as_ptr(),
                message.as_ptr(),
                message.len(),
                context.as_ptr(),
                context.len(),
                self.0.as_ptr(),
            )
        })
    }
}

fn checked(code: i32) -> Result<(), Error> {
    if code == 0 {
        Ok(())
    } else {
        Err(Error::Backend(code))
    }
}

#[cfg(silk_mldsa_native)]
mod ffi {
    unsafe extern "C" {
        #[link_name = "silk_native65_keypair_internal"]
        pub fn keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
        #[link_name = "silk_native65_sign_empty_context"]
        pub fn sign(sig: *mut u8, message: *const u8, len: usize, sk: *const u8) -> i32;
        #[link_name = "silk_native65_verify"]
        pub fn verify(
            sig: *const u8,
            message: *const u8,
            len: usize,
            context: *const u8,
            context_len: usize,
            pk: *const u8,
        ) -> i32;
    }
}

// Unreachable stubs let the same safe API compile without a C toolchain on
// unsupported targets. Availability is checked before every call.
#[cfg(not(silk_mldsa_native))]
mod ffi {
    pub unsafe fn keypair(_: *mut u8, _: *mut u8, _: *const u8) -> i32 {
        unreachable!()
    }
    pub unsafe fn sign(_: *mut u8, _: *const u8, _: usize, _: *const u8) -> i32 {
        unreachable!()
    }
    pub unsafe fn verify(
        _: *const u8,
        _: *const u8,
        _: usize,
        _: *const u8,
        _: usize,
        _: *const u8,
    ) -> i32 {
        unreachable!()
    }
}
