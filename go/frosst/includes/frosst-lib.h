#ifndef FROSST_LIB_H
#define FROSST_LIB_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    const uint8_t *ptr;
    size_t len;
    size_t cap;
} go_slice;

typedef struct {
    const uint8_t *ptr;
    size_t len;
} tss_buffer;

typedef struct {
    int32_t _0;
} Handle;

typedef enum {
    LIB_OK = 0,
    LIB_INVALID_HANDLE = 1,
    LIB_HANDLE_IN_USE = 2,
    LIB_INVALID_HANDLE_TYPE = 3,
    LIB_NULL_PTR = 4,
    LIB_INVALID_BUFFER_SIZE = 5,
    LIB_UNKNOWN_ERROR = 6,
    LIB_SERIALIZATION_ERROR = 7,
    LIB_INVALID_IDENTIFIER = 8,
    LIB_DKG_ERROR = 9,
    LIB_SIGNING_ERROR = 10,
    LIB_RESHARE_ERROR = 11,
    LIB_KEY_IMPORT_ERROR = 12,
    LIB_CKD_ERROR = 13,
    LIB_ADDRESS_ERROR = 14,
    LIB_TX_ERROR = 15,
    LIB_SESSION_NOT_READY = 16,
} lib_error;

void tss_buffer_free(tss_buffer *buf);
lib_error frosst_handle_free(Handle h);

// DKG
lib_error frosst_dkg_part1(uint16_t identifier, uint16_t max_signers, uint16_t min_signers,
                           Handle *out_secret, tss_buffer *out_package);
lib_error frosst_dkg_part2(Handle secret, const go_slice *round1_packages,
                           Handle *out_secret, tss_buffer *out_packages);
lib_error frosst_dkg_part3(Handle secret, const go_slice *round1_packages,
                           const go_slice *round2_packages, uint8_t network, uint64_t birthday,
                           tss_buffer *out_key_share, tss_buffer *out_pub_key);

// Signing
lib_error frosst_sign_commit(const go_slice *key_share,
                             Handle *out_nonces, tss_buffer *out_commitments);
lib_error frosst_sign_create_package(const go_slice *message, const go_slice *commitments_map,
                                     tss_buffer *out_package);
lib_error frosst_sign(const go_slice *signing_package, Handle nonces,
                      const go_slice *key_share, tss_buffer *out_share);
lib_error frosst_sign_aggregate(const go_slice *signing_package, const go_slice *shares_map,
                                const go_slice *key_share, tss_buffer *out_signature);
lib_error frosst_verify_signature(const go_slice *message, const go_slice *signature,
                                  const go_slice *key_share);

// Reshare
lib_error frosst_reshare_part1(uint16_t identifier, uint16_t max_signers, uint16_t min_signers,
                               const go_slice *old_key_share, const go_slice *old_identifiers,
                               Handle *out_secret, tss_buffer *out_package);
lib_error frosst_reshare_part3(Handle secret, const go_slice *round1_packages,
                               const go_slice *round2_packages, const go_slice *expected_vk,
                               uint8_t network, uint64_t birthday,
                               tss_buffer *out_key_share, tss_buffer *out_pub_key);

// Key Import
lib_error frosst_derive_from_seed(const go_slice *seed, uint32_t account_index,
                                  tss_buffer *out_private_key, tss_buffer *out_chain_code,
                                  tss_buffer *out_public_key);
lib_error frosst_key_import_part1(uint16_t identifier, uint16_t max_signers, uint16_t min_signers,
                                  const go_slice *private_key, const go_slice *chain_code,
                                  Handle *out_secret, tss_buffer *out_package);
lib_error frosst_key_import_part3(Handle secret, const go_slice *round1_packages,
                                  const go_slice *round2_packages, const go_slice *expected_vk,
                                  uint8_t network, uint64_t birthday,
                                  tss_buffer *out_key_share, tss_buffer *out_pub_key);

// Address
lib_error frosst_derive_address(const go_slice *key_share, tss_buffer *out_address);
lib_error frosst_pubkey_to_address(const go_slice *pubkey, tss_buffer *out_address);

// KeyShare helpers
lib_error frosst_keyshare_public_key(const go_slice *key_share, tss_buffer *out_pub_key);
lib_error frosst_keyshare_chain_code(const go_slice *key_share, tss_buffer *out_chain_code);
lib_error frosst_keyshare_birthday(const go_slice *key_share, uint64_t *out_birthday);
lib_error frosst_keyshare_identifier(const go_slice *key_share, uint16_t *out_id);
lib_error frosst_private_key_to_public(const go_slice *private_key, tss_buffer *out_pub_key);
lib_error frosst_encode_identifier(uint16_t id, tss_buffer *out_bytes);
lib_error frosst_decode_identifier(const go_slice *id_bytes, uint16_t *out_id);

#endif
