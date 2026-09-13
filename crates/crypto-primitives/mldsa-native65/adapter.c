#include <stddef.h>
#include <stdint.h>
#include "mldsa_native.h"

/* Fixed-size contracts shared with the Rust boundary. */
_Static_assert(MLDSA_PUBLICKEYBYTES(65) == 1952, "public key size");
_Static_assert(MLDSA_SECRETKEYBYTES(65) == 4032, "secret key size");
_Static_assert(MLDSA_BYTES(65) == 3309, "signature size");

int silk_native65_sign_empty_context(uint8_t *sig, const uint8_t *msg,
                                    size_t len, const uint8_t *sk) {
    const uint8_t pre[2] = {0, 0}; /* pure ML-DSA, empty FIPS context */
    const uint8_t rnd[32] = {0};  /* deterministic FIPS 204 mode */
    return silk_native65_signature_internal(sig, msg, len, pre, sizeof pre, rnd, sk, 0);
}
