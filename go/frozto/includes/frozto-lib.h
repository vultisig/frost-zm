/*
 * frozto-lib FFI header (Orchard / RedPallas)
 */
#ifndef _FROZTO_LIB_H
#define _FROZTO_LIB_H

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
    LIB_ORCHARD_ERROR,
    LIB_CKD_ERROR,
    LIB_ADDRESS_ERROR,
    LIB_SESSION_NOT_READY,
    LIB_BLAME = 100,
} lib_error;

uint16_t frost_last_blamed_party(void);

/* Utility */
void tss_buffer_free(tss_buffer *buf);
lib_error frozto_handle_free(Handle h);

/* DKG Keygen */
lib_error frozto_dkg_part1(uint16_t identifier,
                          uint16_t max_signers,
                          uint16_t min_signers,
                          Handle *out_secret,
                          tss_buffer *out_package);

lib_error frozto_dkg_part2(Handle secret,
                          const go_slice *round1_packages,
                          Handle *out_secret,
                          tss_buffer *out_packages);

lib_error frozto_dkg_part3(Handle secret,
                          const go_slice *round1_packages,
                          const go_slice *round2_packages,
                          tss_buffer *out_key_package,
                          tss_buffer *out_pub_key_package);

/* Reshare */
lib_error frozto_reshare_part1(uint16_t identifier,
                              uint16_t max_signers,
                              uint16_t min_signers,
                              const go_slice *old_key_package,
                              const go_slice *old_identifiers,
                              Handle *out_secret,
                              tss_buffer *out_package);

lib_error frozto_reshare_part3(Handle secret,
                              const go_slice *round1_packages,
                              const go_slice *round2_packages,
                              const go_slice *expected_vk,
                              tss_buffer *out_key_package,
                              tss_buffer *out_pub_key_package);

/* Signing */
lib_error frozto_sign_commit(const go_slice *key_package,
                            Handle *out_nonces,
                            tss_buffer *out_commitments);

lib_error frozto_sign_new_package(const go_slice *message,
                                 const go_slice *commitments_map,
                                 const go_slice *pub_key_package,
                                 tss_buffer *out_signing_package,
                                 tss_buffer *out_randomizer_seed);

lib_error frozto_sign(const go_slice *signing_package,
                     Handle nonces,
                     const go_slice *key_package,
                     const go_slice *randomizer_seed,
                     tss_buffer *out_share);

lib_error frozto_sign_aggregate(const go_slice *signing_package,
                               const go_slice *shares_map,
                               const go_slice *pub_key_package,
                               const go_slice *randomizer_seed,
                               tss_buffer *out_signature);

lib_error frozto_verify_signature(const go_slice *message,
                                  const go_slice *signature,
                                  const go_slice *pub_key_package,
                                  const go_slice *randomizer_seed);

/* Identifier encoding */
lib_error frozto_encode_identifier(uint16_t id,
                                  tss_buffer *out_bytes);

lib_error frozto_decode_identifier(const go_slice *id_bytes,
                                  uint16_t *out_id);

/* Key inspection */
lib_error frozto_keypackage_identifier(const go_slice *key_package,
                                      uint16_t *out_id);

lib_error frozto_pubkeypackage_verifying_key(const go_slice *pub_key_package,
                                            tss_buffer *out_key);

/* Key Share Bundle */
lib_error frozto_keyshare_bundle_pack(const go_slice *key_package,
                                      const go_slice *pub_key_package,
                                      const go_slice *orchard_extras,
                                      uint64_t birthday,
                                      tss_buffer *out_bundle);

lib_error frozto_keyshare_bundle_birthday(const go_slice *bundle,
                                          uint64_t *out_birthday);

lib_error frozto_keyshare_bundle_key_package(const go_slice *bundle,
                                             tss_buffer *out_key_package);

lib_error frozto_keyshare_bundle_pub_key_package(const go_slice *bundle,
                                                 tss_buffer *out_pub_key_package);

lib_error frozto_keyshare_bundle_orchard_extras(const go_slice *bundle,
                                                tss_buffer *out_orchard_extras);

/* Key Import */
lib_error frozto_key_import_part1(uint16_t identifier,
                                 uint16_t max_signers,
                                 uint16_t min_signers,
                                 const go_slice *spending_key,
                                 Handle *out_secret,
                                 tss_buffer *out_package,
                                 tss_buffer *out_vk,
                                 tss_buffer *out_extras);

lib_error frozto_key_import_part3(Handle secret,
                                 const go_slice *round1_packages,
                                 const go_slice *round2_packages,
                                 const go_slice *expected_vk,
                                 tss_buffer *out_key_package,
                                 tss_buffer *out_pub_key_package);

/* Orchard */
lib_error frozto_orchard_generate_extras(tss_buffer *out_orchard_extras);

lib_error frozto_orchard_derive_keys(const go_slice *pub_key_package,
                                     const go_slice *orchard_extras,
                                     tss_buffer *out_address,
                                     tss_buffer *out_ivk);

lib_error frozto_orchard_try_decrypt_compact(const go_slice *ivk,
                                            const go_slice *nullifier,
                                            const go_slice *cmx,
                                            const go_slice *ephemeral_key,
                                            const go_slice *ciphertext,
                                            uint64_t *out_value);

lib_error frozto_orchard_decrypt_note_full(const go_slice *ivk,
                                          const go_slice *nullifier,
                                          const go_slice *cmx,
                                          const go_slice *ephemeral_key,
                                          const go_slice *enc_ciphertext,
                                          tss_buffer *out_note_data);

lib_error frozto_orchard_compute_nullifier(const go_slice *pkp_bytes,
                                           const go_slice *extras_bytes,
                                           const go_slice *note_data,
                                           tss_buffer *out_nullifier);

/* Orchard DFVK construction */
lib_error frozto_orchard_build_fvk(const go_slice *pub_key_package,
                                   const go_slice *orchard_extras,
                                   tss_buffer *out_fvk);

/* Commitment Tree */
lib_error frozto_tree_new(Handle *out_handle);

lib_error frozto_tree_append(Handle tree,
                             const go_slice *cmx);

lib_error frozto_tree_serialize(Handle tree,
                                tss_buffer *out_data);

lib_error frozto_tree_deserialize(const go_slice *data,
                                  Handle *out_handle);

lib_error frozto_tree_free(Handle tree);

/* Ceremony Metadata */
lib_error frozto_keygen_metadata_create(uint64_t birthday,
                                        tss_buffer *out_extras,
                                        tss_buffer *out_metadata);

lib_error frozto_keygen_metadata_create_with_extras(const go_slice *extras,
                                                    uint64_t birthday,
                                                    tss_buffer *out_metadata);

lib_error frozto_keygen_metadata_parse(const go_slice *metadata,
                                       tss_buffer *out_extras,
                                       uint64_t *out_birthday);

lib_error frozto_keygen_metadata_hash(const go_slice *metadata,
                                      tss_buffer *out_hash);

/* Session-based DKG */
lib_error frozto_dkg_setupmsg_new(uint16_t max_signers,
                                  uint16_t min_signers,
                                  const go_slice *parties_data,
                                  uint64_t birthday,
                                  tss_buffer *out_setup);

lib_error frozto_dkg_session_from_setup(const go_slice *setup_data,
                                        const go_slice *my_party_name,
                                        Handle *out_handle);

lib_error frozto_dkg_session_feed(Handle session,
                                  const go_slice *msg,
                                  int32_t *out_finished);

lib_error frozto_dkg_session_take_msg(Handle session,
                                      tss_buffer *out_message);

lib_error frozto_dkg_session_msg_receiver(Handle session,
                                          const go_slice *msg,
                                          uint32_t index,
                                          tss_buffer *out_receiver);

lib_error frozto_dkg_session_result(Handle session,
                                    tss_buffer *out_bundle);

lib_error frozto_dkg_session_free(Handle session);

/* Session-based Key Import */
lib_error frozto_key_import_setupmsg_new(uint16_t max_signers,
                                         uint16_t min_signers,
                                         const go_slice *parties_data,
                                         uint64_t birthday,
                                         uint16_t seed_holder_id,
                                         const go_slice *seed,
                                         uint32_t account_index,
                                         tss_buffer *out_setup);

lib_error frozto_key_import_session_from_setup(const go_slice *setup_data,
                                               const go_slice *my_party_name,
                                               Handle *out_handle);

lib_error frozto_key_import_session_feed(Handle session,
                                         const go_slice *msg,
                                         int32_t *out_finished);

lib_error frozto_key_import_session_take_msg(Handle session,
                                             tss_buffer *out_message);

lib_error frozto_key_import_session_msg_receiver(Handle session,
                                                 const go_slice *msg,
                                                 uint32_t index,
                                                 tss_buffer *out_receiver);

lib_error frozto_key_import_session_result(Handle session,
                                           tss_buffer *out_bundle);

lib_error frozto_key_import_session_free(Handle session);

/* Session-based Signing */
lib_error frozto_sign_setupmsg_new(const go_slice *msg_to_sign,
                                   const go_slice *parties_data,
                                   tss_buffer *out_setup);

lib_error frozto_sign_session_from_setup(const go_slice *setup_data,
                                         const go_slice *my_party_name,
                                         const go_slice *key_package,
                                         const go_slice *pub_key_package,
                                         Handle *out_handle);

lib_error frozto_sign_session_from_setup_with_alpha(const go_slice *setup_data,
                                                    const go_slice *my_party_name,
                                                    const go_slice *key_package,
                                                    const go_slice *pub_key_package,
                                                    const go_slice *alpha,
                                                    Handle *out_handle);

lib_error frozto_sign_session_feed(Handle session,
                                   const go_slice *msg,
                                   int32_t *out_finished);

lib_error frozto_sign_session_take_msg(Handle session,
                                       tss_buffer *out_message);

lib_error frozto_sign_session_msg_receiver(Handle session,
                                           const go_slice *msg,
                                           uint32_t index,
                                           tss_buffer *out_receiver);

lib_error frozto_sign_session_result(Handle session,
                                     tss_buffer *out_signature);

lib_error frozto_sign_session_free(Handle session);

/* Session-based Reshare */
lib_error frozto_reshare_setupmsg_new(uint16_t max_signers,
                                      uint16_t min_signers,
                                      const go_slice *parties_data,
                                      const go_slice *old_identifiers,
                                      const go_slice *expected_vk,
                                      tss_buffer *out_setup);

lib_error frozto_reshare_session_from_setup(const go_slice *setup_data,
                                            const go_slice *my_party_name,
                                            const go_slice *old_key_package,
                                            Handle *out_handle);

lib_error frozto_reshare_session_feed(Handle session,
                                      const go_slice *msg,
                                      int32_t *out_finished);

lib_error frozto_reshare_session_take_msg(Handle session,
                                          tss_buffer *out_message);

lib_error frozto_reshare_session_msg_receiver(Handle session,
                                              const go_slice *msg,
                                              uint32_t index,
                                              tss_buffer *out_receiver);

lib_error frozto_reshare_session_result(Handle session,
                                        tss_buffer *out_key_package,
                                        tss_buffer *out_pub_key_package);

lib_error frozto_reshare_session_free(Handle session);

#endif /* _FROZTO_LIB_H */
