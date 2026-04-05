/*
 * frozts-sdk FFI header
 */
#ifndef _FROZT_SDK_H
#define _FROZT_SDK_H

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
    LIB_SAPLING_ERROR,
} lib_error;

void tss_buffer_free(tss_buffer *buf);

/* Scanner */
lib_error frozts_scan(const go_slice *dfvk,
                      const go_slice *url,
                      uint64_t birthday,
                      tss_buffer *out_result);

lib_error frozts_scan_balance(const go_slice *dfvk,
                              const go_slice *url,
                              uint64_t birthday,
                              uint64_t *out_balance);

#endif /* _FROZT_SDK_H */
