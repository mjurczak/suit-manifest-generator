#include "stubs.h"
#include "suit_bootloader.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define SUIT_BOOTLOADER_SLOT_A_OFFSET 0x8000
#define SUIT_BOOTLOADER_SLOT_B_OFFSET 0x84000

static void *low_mem_limit;
static void *hi_mem_limit;

const entrypoint_t entrypoints[] = {
    {
        SUIT_BOOTLOADER_SLOT_A_OFFSET + SUIT_BOOTLOADER_HEADER_SIZE,
        SUIT_BOOTLOADER_SLOT_A_OFFSET
    },
    {
        SUIT_BOOTLOADER_SLOT_B_OFFSET + SUIT_BOOTLOADER_HEADER_SIZE,
        SUIT_BOOTLOADER_SLOT_B_OFFSET
    }
};
const size_t n_entrypoints = 2;

void check_input_valid_mem_range(const char *caller, void *ptr)
{
    if (ptr < low_mem_limit || ptr > hi_mem_limit)
    {
        printf("Out of bound memory access detected in %s.\r\n", caller);
        printf("Low memory limit: %p\r\n", low_mem_limit);
        printf("Hi memory limit: %p\r\n", hi_mem_limit);
        printf("Access detected at: %p\r\n", ptr);
        exit(1);
    }
}

void mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
    (void)ctx;
}

int mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 )
{
    (void)ctx;
    (void)is224;
    return 0;
}

int mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
                               const unsigned char *input,
                               size_t ilen )
{
    
    return 0;
}

int mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
                               unsigned char output[32] )
{
    (void)ctx;
    (void)output;
    return 0;
}

void mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
    (void)ctx;
}

void mbed_start_application(uintptr_t appptr)
{
    (void)appptr;
    /* Will never get here. */
}
/*
int uECC_verify(const uint8_t private_key[uECC_BYTES*2],
                const uint8_t hash[uECC_BYTES],
                const uint8_t signature[uECC_BYTES*2])
{
    // Ignore priv key and hash
    (void)private_key;
    (void)hash;

    // Test if the provided signature is entirely within the input COSE memory
    check_input_valid_mem_range(__PRETTY_FUNCTION__, (void*)signature);
    check_input_valid_mem_range(__PRETTY_FUNCTION__, (void*)(signature + uECC_BYTES*2));

    // For the purpose of test - always fail signature validation.
    return 0;
}
*/
void set_input_valid_mem_range(void *low, void *high)
{
    low_mem_limit = low;
    hi_mem_limit = high;
}