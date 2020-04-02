#include "stubs.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "suit_bootloader.h"
#include "suit_parser.h"

uint8_t simple_bad_input[] = {0xA1,0x03,0x40};

/* An example of crashing the parser by null ptr access.
 *
 */
int main(int argc, char *argv[]) 
{
    int result_code = 0;
    result_code = suit_do_process_manifest(simple_bad_input, sizeof(simple_bad_input));
    printf("Result code: %d\r\n", result_code);
    return 0;
}
