/*
 * fromt-sdk FFI header
 */
#ifndef _FROMT_SDK_H
#define _FROMT_SDK_H

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
    LIB_CKD_ERROR,
    LIB_ADDRESS_ERROR,
} lib_error;

void tss_buffer_free(tss_buffer *buf);

/* Scan */
lib_error fromt_scan_balance(const go_slice *key_share,
                              const go_slice *daemon_url,
                              uint64_t birthday,
                              const go_slice *spend_key,
                              uint64_t *out_balance,
                              uint32_t *out_num_outputs);

/* Scan Outputs */
lib_error fromt_scan_outputs(const go_slice *key_share,
                              const go_slice *daemon_url,
                              uint64_t birthday,
                              tss_buffer *out_data);

/* Filter Spent Outputs */
lib_error fromt_filter_spent_outputs(const go_slice *outputs_data,
                                      const go_slice *spent_flags,
                                      uint64_t *out_balance,
                                      uint32_t *out_num_outputs);

/* Spend Prepare */
lib_error fromt_spend_prepare(const go_slice *key_share,
                               const go_slice *daemon_url,
                               const go_slice *recipient,
                               uint64_t amount, uint64_t birthday,
                               const go_slice *excluded_offsets,
                               const go_slice *spend_key,
                               tss_buffer *out_signable_tx,
                               tss_buffer *out_spent_offsets);

#endif /* _FROMT_SDK_H */
