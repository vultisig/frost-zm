#ifndef FROMT_LIB_H
#define FROMT_LIB_H

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
    LIB_SESSION_NOT_READY = 15,
} lib_error;

/* Utility */
void tss_buffer_free(tss_buffer *buf);
lib_error fromt_handle_free(Handle h);

/* DKG */
lib_error fromt_dkg_part1(uint16_t identifier, uint16_t max_signers,
                          uint16_t min_signers,
                          Handle *out_secret, tss_buffer *out_package);

lib_error fromt_dkg_part2(Handle secret, const go_slice *round1_packages,
                          Handle *out_secret, tss_buffer *out_packages);

lib_error fromt_dkg_part3(Handle secret, const go_slice *round1_packages,
                          const go_slice *round2_packages, uint8_t network,
                          uint64_t birthday,
                          tss_buffer *out_key_share, tss_buffer *out_pub_key);

/* Key Import */
lib_error fromt_key_import_part1(uint16_t identifier, uint16_t max_signers,
                                 uint16_t min_signers,
                                 const go_slice *spend_key,
                                 Handle *out_secret, tss_buffer *out_package);

lib_error fromt_key_import_part3(Handle secret, const go_slice *round1_packages,
                                 const go_slice *round2_packages,
                                 const go_slice *expected_vk, uint8_t network,
                                 uint64_t birthday,
                                 tss_buffer *out_key_share,
                                 tss_buffer *out_pub_key);

/* Seed Derivation */
lib_error fromt_derive_keys_from_seed(const go_slice *seed,
                                      tss_buffer *out_spend_key,
                                      tss_buffer *out_view_key);

lib_error fromt_spend_key_to_public(const go_slice *spend_key,
                                    tss_buffer *out_pub_key);

/* Signing */
lib_error fromt_sign_commit(const go_slice *key_share,
                            Handle *out_nonces, tss_buffer *out_commitments);

lib_error fromt_sign_create_package(const go_slice *message,
                                    const go_slice *commitments_map,
                                    tss_buffer *out_signing_package);

lib_error fromt_sign(const go_slice *signing_package, Handle nonces,
                     const go_slice *key_share, tss_buffer *out_share);

lib_error fromt_sign_aggregate(const go_slice *signing_package,
                               const go_slice *shares_map,
                               const go_slice *key_share,
                               tss_buffer *out_signature);

lib_error fromt_verify_signature(const go_slice *message,
                                  const go_slice *signature,
                                  const go_slice *key_share);

/* Reshare */
lib_error fromt_reshare_part1(uint16_t identifier, uint16_t max_signers,
                              uint16_t min_signers,
                              const go_slice *old_key_share,
                              const go_slice *old_identifiers,
                              Handle *out_secret, tss_buffer *out_package);

lib_error fromt_reshare_part3(Handle secret, const go_slice *round1_packages,
                              const go_slice *round2_packages,
                              const go_slice *expected_vk, uint8_t network,
                              uint64_t birthday,
                              tss_buffer *out_key_share,
                              tss_buffer *out_pub_key);

/* CKD */
lib_error fromt_ckd_part1(const go_slice *key_share, uint32_t account,
                          uint32_t index, const go_slice *signer_ids,
                          Handle *out_state, tss_buffer *out_package);

lib_error fromt_ckd_part2(Handle state, const go_slice *r1_packages,
                          tss_buffer *out_child_key_share);

/* Address */
lib_error fromt_derive_address(const go_slice *key_share,
                               tss_buffer *out_address);

lib_error fromt_derive_subaddress(const go_slice *key_share,
                                  uint32_t account, uint32_t index,
                                  tss_buffer *out_address);

/* Key Share Inspection */
lib_error fromt_keyshare_public_key(const go_slice *key_share,
                                    tss_buffer *out_pub_key);

lib_error fromt_keyshare_view_key(const go_slice *key_share,
                                  tss_buffer *out_view_key);

lib_error fromt_keyshare_identifier(const go_slice *key_share,
                                    uint16_t *out_id);

lib_error fromt_keyshare_birthday(const go_slice *key_share,
                                  uint64_t *out_birthday);

/* Identifier Encoding */
lib_error fromt_encode_identifier(uint16_t id, tss_buffer *out_bytes);

lib_error fromt_decode_identifier(const go_slice *id_bytes, uint16_t *out_id);

/* Scan */
lib_error fromt_scan_balance(const go_slice *key_share,
                              const go_slice *daemon_url,
                              uint64_t birthday,
                              const go_slice *spend_key,
                              uint64_t *out_balance,
                              uint32_t *out_num_outputs);

/* Spend */
lib_error fromt_spend_prepare(const go_slice *key_share,
                               const go_slice *daemon_url,
                               const go_slice *recipient,
                               uint64_t amount, uint64_t birthday,
                               const go_slice *excluded_offsets,
                               const go_slice *spend_key,
                               tss_buffer *out_signable_tx,
                               tss_buffer *out_spent_offsets);

lib_error fromt_spend_preprocess(const go_slice *key_share,
                                  const go_slice *signable_tx,
                                  Handle *out_handle,
                                  tss_buffer *out_preprocess);

lib_error fromt_spend_sign(Handle handle,
                            const go_slice *preprocesses_map,
                            Handle *out_handle,
                            tss_buffer *out_share);

lib_error fromt_spend_complete(Handle handle,
                                const go_slice *shares_map,
                                tss_buffer *out_raw_tx);

/* Session-based DKG */
lib_error fromt_dkg_setupmsg_new(uint16_t max_signers,
                                  uint16_t min_signers,
                                  const go_slice *parties_data,
                                  uint8_t network,
                                  uint64_t birthday,
                                  tss_buffer *out_setup);

lib_error fromt_dkg_session_from_setup(const go_slice *setup_data,
                                        const go_slice *my_party_name,
                                        Handle *out_handle);

lib_error fromt_dkg_session_feed(Handle session,
                                  const go_slice *msg,
                                  int32_t *out_finished);

lib_error fromt_dkg_session_take_msg(Handle session,
                                      tss_buffer *out_message);

lib_error fromt_dkg_session_msg_receiver(Handle session,
                                          const go_slice *msg,
                                          uint32_t index,
                                          tss_buffer *out_receiver);

lib_error fromt_dkg_session_result(Handle session,
                                    tss_buffer *out_bundle);

lib_error fromt_dkg_session_free(Handle session);

/* Session-based Key Import */
lib_error fromt_key_import_setupmsg_new(uint16_t max_signers,
                                         uint16_t min_signers,
                                         const go_slice *parties_data,
                                         uint8_t network,
                                         uint64_t birthday,
                                         uint16_t seed_holder_id,
                                         const go_slice *spend_key,
                                         tss_buffer *out_setup);

lib_error fromt_key_import_session_from_setup(const go_slice *setup_data,
                                               const go_slice *my_party_name,
                                               Handle *out_handle);

lib_error fromt_key_import_session_feed(Handle session,
                                         const go_slice *msg,
                                         int32_t *out_finished);

lib_error fromt_key_import_session_take_msg(Handle session,
                                             tss_buffer *out_message);

lib_error fromt_key_import_session_msg_receiver(Handle session,
                                                 const go_slice *msg,
                                                 uint32_t index,
                                                 tss_buffer *out_receiver);

lib_error fromt_key_import_session_result(Handle session,
                                           tss_buffer *out_bundle);

lib_error fromt_key_import_session_free(Handle session);

/* Session-based Signing */
lib_error fromt_sign_setupmsg_new(const go_slice *msg_to_sign,
                                   const go_slice *parties_data,
                                   tss_buffer *out_setup);

lib_error fromt_sign_session_from_setup(const go_slice *setup_data,
                                         const go_slice *my_party_name,
                                         const go_slice *key_package,
                                         const go_slice *pub_key_package,
                                         Handle *out_handle);

lib_error fromt_sign_session_feed(Handle session,
                                   const go_slice *msg,
                                   int32_t *out_finished);

lib_error fromt_sign_session_take_msg(Handle session,
                                       tss_buffer *out_message);

lib_error fromt_sign_session_msg_receiver(Handle session,
                                           const go_slice *msg,
                                           uint32_t index,
                                           tss_buffer *out_receiver);

lib_error fromt_sign_session_result(Handle session,
                                     tss_buffer *out_signature);

lib_error fromt_sign_session_free(Handle session);

/* Session-based Reshare */
lib_error fromt_reshare_setupmsg_new(uint16_t max_signers,
                                      uint16_t min_signers,
                                      const go_slice *parties_data,
                                      const go_slice *old_identifiers,
                                      const go_slice *expected_vk,
                                      tss_buffer *out_setup);

lib_error fromt_reshare_session_from_setup(const go_slice *setup_data,
                                            const go_slice *my_party_name,
                                            const go_slice *old_key_package,
                                            Handle *out_handle);

lib_error fromt_reshare_session_feed(Handle session,
                                      const go_slice *msg,
                                      int32_t *out_finished);

lib_error fromt_reshare_session_take_msg(Handle session,
                                          tss_buffer *out_message);

lib_error fromt_reshare_session_msg_receiver(Handle session,
                                              const go_slice *msg,
                                              uint32_t index,
                                              tss_buffer *out_receiver);

lib_error fromt_reshare_session_result(Handle session,
                                        tss_buffer *out_key_package,
                                        tss_buffer *out_pub_key_package);

lib_error fromt_reshare_session_free(Handle session);

#endif /* FROMT_LIB_H */
