#include <stdio.h> 
#include "rijndael.h"
#define NUM_LOOPS 10000000
int main(){
    // Test Vector
    u8 input[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    u8 key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    u8 output[16];
    u32 ExpandedKey[44];
    rijndaelKeySetupEnc(ExpandedKey, key);
    for (size_t i = 0; i < 44; i++)
        printf("%02x\n", ExpandedKey[i]);
    rijndaelEncrypt(ExpandedKey, input, output);
    printf("Encrypted output:\n");
	for (int i = 0; i < 16; ++i)
        printf("%02x ", output[i]);
    //Performance Check
    printf("\n");
    for (int i=0; i < NUM_LOOPS; i++){
		rijndaelEncrypt(ExpandedKey, input, output);
    	input[1]++;
    }
    return 0;
}
