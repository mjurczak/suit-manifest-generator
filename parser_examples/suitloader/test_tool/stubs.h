#ifndef _STUBS_H
#define _STUBS_H

#include <stdint.h>
#include <stddef.h>

//#define uECC_BYTES (32)
#define SUIT_BOOTLOADER_HEADER_SIZE  (0x400)

#define CHECK_PTR(ptr) check_input_valid_mem_range(__PRETTY_FUNCTION__, ptr)

typedef struct mbedtls_sha256_context
{
}
mbedtls_sha256_context;

void mbedtls_sha256_init( mbedtls_sha256_context *ctx );
int mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 );
int mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
                               const unsigned char *input,
                               size_t ilen );
int mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
                               unsigned char output[32] );
void mbedtls_sha256_free( mbedtls_sha256_context *ctx );

void mbed_start_application(uintptr_t appptr);

/*
int uECC_verify(const uint8_t private_key[uECC_BYTES*2],
                const uint8_t hash[uECC_BYTES],
                const uint8_t signature[uECC_BYTES*2]);
*/

void set_input_valid_mem_range(void *low, void *high);
void check_input_valid_mem_range(const char *caller, void *ptr);

#endif /* #ifndef _STUBS_H */