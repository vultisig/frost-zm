/*
 * froeth-lib FFI header
 */
#ifndef _FROETH_LIB_H
#define _FROETH_LIB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

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
    LIB_INVALID_HANDLE,
    LIB_HANDLE_IN_USE,
    LIB_INVALID_HANDLE_TYPE,
    LIB_NULL_PTR,
    LIB_INVALID_BUFFER_SIZE,
    LIB_UNKNOWN_ERROR,
    LIB_SERIALIZATION_ERROR,
    LIB_INVALID_IDENTIFIER,
    LIB_DKG_ERROR,
    LIB_SIGNING_ERROR,
    LIB_RESHARE_ERROR,
    LIB_KEY_IMPORT_ERROR,
    LIB_SAPLING_ERROR,
    LIB_CKD_ERROR,
    LIB_ADDRESS_ERROR,
    LIB_SESSION_NOT_READY,
} lib_error;

/* Utility */
void tss_buffer_free(tss_buffer *buf);
lib_error froeth_handle_free(Handle h);

/* DKG Keygen */
lib_error froeth_dkg_part1(uint16_t identifier,
                           uint16_t max_signers,
                           uint16_t min_signers,
                           Handle *out_secret,
                           tss_buffer *out_package);

lib_error froeth_dkg_part2(Handle secret,
                           const go_slice *round1_packages,
                           Handle *out_secret,
                           tss_buffer *out_packages);

lib_error froeth_dkg_part3(Handle secret,
                           const go_slice *round1_packages,
                           const go_slice *round2_packages,
                           uint8_t network,
                           uint64_t birthday,
                           tss_buffer *out_key_share,
                           tss_buffer *out_pub_key);

/* Reshare */
lib_error froeth_reshare_part1(uint16_t identifier,
                               uint16_t max_signers,
                               uint16_t min_signers,
                               const go_slice *old_key_share,
                               const go_slice *old_identifiers,
                               Handle *out_secret,
                               tss_buffer *out_package);

lib_error froeth_reshare_part3(Handle secret,
                               const go_slice *round1_packages,
                               const go_slice *round2_packages,
                               const go_slice *expected_vk,
                               uint8_t network,
                               uint64_t birthday,
                               tss_buffer *out_key_share,
                               tss_buffer *out_pub_key);

/* Signing */
lib_error froeth_sign_commit(const go_slice *key_share,
                             Handle *out_nonces,
                             tss_buffer *out_commitments);

lib_error froeth_sign_create_package(const go_slice *message,
                                     const go_slice *commitments_map,
                                     tss_buffer *out_package);

lib_error froeth_sign(const go_slice *signing_package,
                      Handle nonces,
                      const go_slice *key_share,
                      tss_buffer *out_share);

lib_error froeth_sign_aggregate(const go_slice *signing_package,
                                const go_slice *shares_map,
                                const go_slice *key_share,
                                tss_buffer *out_signature);

lib_error froeth_verify_signature(const go_slice *message,
                                  const go_slice *signature,
                                  const go_slice *key_share);

/* Key Import */
lib_error froeth_derive_from_seed(const go_slice *seed,
                                  uint32_t account_index,
                                  tss_buffer *out_private_key,
                                  tss_buffer *out_chain_code,
                                  tss_buffer *out_public_key);

lib_error froeth_key_import_part1(uint16_t identifier,
                                  uint16_t max_signers,
                                  uint16_t min_signers,
                                  const go_slice *private_key,
                                  const go_slice *chain_code,
                                  Handle *out_secret,
                                  tss_buffer *out_package);

lib_error froeth_key_import_part3(Handle secret,
                                  const go_slice *round1_packages,
                                  const go_slice *round2_packages,
                                  const go_slice *expected_vk,
                                  uint8_t network,
                                  uint64_t birthday,
                                  tss_buffer *out_key_share,
                                  tss_buffer *out_pub_key);

/* CKD */
lib_error froeth_ckd_derive(const go_slice *key_share,
                            uint32_t change,
                            uint32_t index,
                            tss_buffer *out_child_key_share);

lib_error froeth_derive_child_pubkey(const go_slice *key_share,
                                     uint32_t change,
                                     uint32_t index,
                                     tss_buffer *out_pubkey);

/* Address */
lib_error froeth_derive_address(const go_slice *key_share,
                                uint32_t change,
                                uint32_t index,
                                tss_buffer *out_address);

lib_error froeth_derive_root_address(const go_slice *key_share,
                                     tss_buffer *out_address);

lib_error froeth_eth_address(const go_slice *verifying_key,
                             tss_buffer *out_address);

/* KeyShare helpers */
lib_error froeth_keyshare_public_key(const go_slice *key_share, tss_buffer *out_pub_key);
lib_error froeth_keyshare_chain_code(const go_slice *key_share, tss_buffer *out_chain_code);
lib_error froeth_keyshare_birthday(const go_slice *key_share, uint64_t *out_birthday);
lib_error froeth_keyshare_identifier(const go_slice *key_share, uint16_t *out_id);
lib_error froeth_private_key_to_public(const go_slice *private_key, tss_buffer *out_pub_key);
lib_error froeth_encode_identifier(uint16_t id, tss_buffer *out_bytes);
lib_error froeth_decode_identifier(const go_slice *id_bytes, uint16_t *out_id);

#endif /* _FROETH_LIB_H */
