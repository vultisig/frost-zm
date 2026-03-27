#ifndef FROBT_LIB_H
#define FROBT_LIB_H

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

/* Utility */
void tss_buffer_free(tss_buffer *buf);
lib_error frobt_handle_free(Handle h);

/* DKG */
lib_error frobt_dkg_part1(uint16_t identifier, uint16_t max_signers,
                          uint16_t min_signers,
                          Handle *out_secret, tss_buffer *out_package);

lib_error frobt_dkg_part2(Handle secret, const go_slice *round1_packages,
                          Handle *out_secret, tss_buffer *out_packages);

lib_error frobt_dkg_part3(Handle secret, const go_slice *round1_packages,
                          const go_slice *round2_packages, uint8_t network,
                          uint64_t birthday,
                          tss_buffer *out_key_share, tss_buffer *out_pub_key);

/* Key Import */
lib_error frobt_derive_from_seed(const go_slice *seed, uint32_t account_index,
                                 tss_buffer *out_private_key,
                                 tss_buffer *out_chain_code,
                                 tss_buffer *out_public_key);

lib_error frobt_key_import_part1(uint16_t identifier, uint16_t max_signers,
                                 uint16_t min_signers,
                                 const go_slice *private_key,
                                 const go_slice *chain_code,
                                 Handle *out_secret, tss_buffer *out_package);

lib_error frobt_key_import_part3(Handle secret, const go_slice *round1_packages,
                                 const go_slice *round2_packages,
                                 const go_slice *expected_vk, uint8_t network,
                                 uint64_t birthday,
                                 tss_buffer *out_key_share,
                                 tss_buffer *out_pub_key);

lib_error frobt_private_key_to_public(const go_slice *private_key,
                                      tss_buffer *out_pub_key);

/* Signing */
lib_error frobt_sign_commit(const go_slice *key_share,
                            Handle *out_nonces, tss_buffer *out_commitments);

lib_error frobt_sign_create_package(const go_slice *message,
                                    const go_slice *commitments_map,
                                    tss_buffer *out_signing_package);

lib_error frobt_sign(const go_slice *signing_package, Handle nonces,
                     const go_slice *key_share, tss_buffer *out_share);

lib_error frobt_sign_aggregate(const go_slice *signing_package,
                               const go_slice *shares_map,
                               const go_slice *key_share,
                               tss_buffer *out_signature);

lib_error frobt_verify_signature(const go_slice *message,
                                  const go_slice *signature,
                                  const go_slice *key_share);

/* Taproot Signing */
lib_error frobt_sign_taproot(const go_slice *signing_package, Handle nonces,
                             const go_slice *key_share,
                             const go_slice *merkle_root,
                             tss_buffer *out_share);

lib_error frobt_sign_aggregate_taproot(const go_slice *signing_package,
                                       const go_slice *shares_map,
                                       const go_slice *key_share,
                                       const go_slice *merkle_root,
                                       tss_buffer *out_signature);

lib_error frobt_verify_taproot_signature(const go_slice *message,
                                          const go_slice *signature,
                                          const go_slice *key_share,
                                          const go_slice *merkle_root);

lib_error frobt_compute_taproot_output_key(const go_slice *verifying_key,
                                            const go_slice *merkle_root,
                                            tss_buffer *out_output_key);

/* Reshare */
lib_error frobt_reshare_part1(uint16_t identifier, uint16_t max_signers,
                              uint16_t min_signers,
                              const go_slice *old_key_share,
                              const go_slice *old_identifiers,
                              Handle *out_secret, tss_buffer *out_package);

lib_error frobt_reshare_part3(Handle secret, const go_slice *round1_packages,
                              const go_slice *round2_packages,
                              const go_slice *expected_vk, uint8_t network,
                              uint64_t birthday,
                              tss_buffer *out_key_share,
                              tss_buffer *out_pub_key);

/* CKD */
lib_error frobt_ckd_derive(const go_slice *key_share,
                           uint32_t change, uint32_t index,
                           tss_buffer *out_child_key_share);

lib_error frobt_derive_child_pubkey(const go_slice *key_share,
                                    uint32_t change, uint32_t index,
                                    tss_buffer *out_pubkey);

/* Address */
lib_error frobt_derive_address(const go_slice *key_share,
                               uint32_t change, uint32_t index,
                               tss_buffer *out_address);

lib_error frobt_derive_root_address(const go_slice *key_share,
                                    tss_buffer *out_address);

lib_error frobt_derive_address_from_pubkey(const go_slice *pubkey,
                                           uint8_t network,
                                           tss_buffer *out_address);

/* Transaction */
lib_error frobt_compute_sighash(const go_slice *raw_tx,
                                const go_slice *prevouts,
                                uint32_t input_index,
                                uint8_t sighash_type,
                                tss_buffer *out_sighash);

lib_error frobt_attach_witness(const go_slice *raw_tx,
                               uint32_t input_index,
                               const go_slice *signature,
                               tss_buffer *out_signed_tx);

/* Key Share Inspection */
lib_error frobt_keyshare_public_key(const go_slice *key_share,
                                    tss_buffer *out_pub_key);

lib_error frobt_keyshare_chain_code(const go_slice *key_share,
                                    tss_buffer *out_chain_code);

lib_error frobt_keyshare_birthday(const go_slice *key_share,
                                  uint64_t *out_birthday);

lib_error frobt_keyshare_identifier(const go_slice *key_share,
                                    uint16_t *out_id);

/* Identifier Encoding */
lib_error frobt_encode_identifier(uint16_t id, tss_buffer *out_bytes);

lib_error frobt_decode_identifier(const go_slice *id_bytes, uint16_t *out_id);

/* Session-based DKG */
lib_error frobt_dkg_setupmsg_new(uint16_t max_signers,
                                  uint16_t min_signers,
                                  const go_slice *parties_data,
                                  uint8_t network,
                                  uint64_t birthday,
                                  tss_buffer *out_setup);

lib_error frobt_dkg_session_from_setup(const go_slice *setup_data,
                                        const go_slice *my_party_name,
                                        Handle *out_handle);

lib_error frobt_dkg_session_feed(Handle session,
                                  const go_slice *msg,
                                  int32_t *out_finished);

lib_error frobt_dkg_session_take_msg(Handle session,
                                      tss_buffer *out_message);

lib_error frobt_dkg_session_msg_receiver(Handle session,
                                          const go_slice *msg,
                                          uint32_t index,
                                          tss_buffer *out_receiver);

lib_error frobt_dkg_session_result(Handle session,
                                    tss_buffer *out_bundle);

lib_error frobt_dkg_session_free(Handle session);

/* Session-based Signing */
lib_error frobt_sign_setupmsg_new(const go_slice *msg_to_sign,
                                   const go_slice *parties_data,
                                   tss_buffer *out_setup);

lib_error frobt_sign_session_from_setup(const go_slice *setup_data,
                                         const go_slice *my_party_name,
                                         const go_slice *key_package,
                                         const go_slice *pub_key_package,
                                         Handle *out_handle);

lib_error frobt_sign_session_feed(Handle session,
                                   const go_slice *msg,
                                   int32_t *out_finished);

lib_error frobt_sign_session_take_msg(Handle session,
                                       tss_buffer *out_message);

lib_error frobt_sign_session_msg_receiver(Handle session,
                                           const go_slice *msg,
                                           uint32_t index,
                                           tss_buffer *out_receiver);

lib_error frobt_sign_session_result(Handle session,
                                     tss_buffer *out_signature);

lib_error frobt_sign_session_free(Handle session);

/* Session-based Reshare */
lib_error frobt_reshare_setupmsg_new(uint16_t max_signers,
                                      uint16_t min_signers,
                                      const go_slice *parties_data,
                                      const go_slice *old_identifiers,
                                      const go_slice *expected_vk,
                                      tss_buffer *out_setup);

lib_error frobt_reshare_session_from_setup(const go_slice *setup_data,
                                            const go_slice *my_party_name,
                                            const go_slice *old_key_package,
                                            Handle *out_handle);

lib_error frobt_reshare_session_feed(Handle session,
                                      const go_slice *msg,
                                      int32_t *out_finished);

lib_error frobt_reshare_session_take_msg(Handle session,
                                          tss_buffer *out_message);

lib_error frobt_reshare_session_msg_receiver(Handle session,
                                              const go_slice *msg,
                                              uint32_t index,
                                              tss_buffer *out_receiver);

lib_error frobt_reshare_session_result(Handle session,
                                        tss_buffer *out_key_package,
                                        tss_buffer *out_pub_key_package);

lib_error frobt_reshare_session_free(Handle session);

/* Session-based Key Import */
lib_error frobt_key_import_setupmsg_new(uint16_t max_signers,
                                         uint16_t min_signers,
                                         const go_slice *parties_data,
                                         uint8_t network,
                                         uint64_t birthday,
                                         uint16_t seed_holder_id,
                                         const go_slice *private_key,
                                         const go_slice *chain_code,
                                         tss_buffer *out_setup);

lib_error frobt_key_import_session_from_setup(const go_slice *setup_data,
                                               const go_slice *my_party_name,
                                               Handle *out_handle);

lib_error frobt_key_import_session_feed(Handle session,
                                         const go_slice *msg,
                                         int32_t *out_finished);

lib_error frobt_key_import_session_take_msg(Handle session,
                                             tss_buffer *out_message);

lib_error frobt_key_import_session_msg_receiver(Handle session,
                                                 const go_slice *msg,
                                                 uint32_t index,
                                                 tss_buffer *out_receiver);

lib_error frobt_key_import_session_result(Handle session,
                                           tss_buffer *out_bundle);

lib_error frobt_key_import_session_free(Handle session);

#endif /* FROBT_LIB_H */
