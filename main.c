#include <stdio.h>
#include <emmintrin.h>  // SSE2 header for SIMD
#include "encrypt.h"
#include "decrypt.h"
#include "ecbcbc.h"

void print_usage(char *program_name) {
    printf("Usage: %s <operation> <mode_of_operation> <inputfile> <outputfile> <key>\n", program_name);
    printf("Modes:\n");
    printf("  encrypt(e): Encrypt the input plaintext\n");
    printf("  decrypt(d): Decrypt the input ciphertext\n");
    printf("Modes of operation:\n");
    printf("  ecb(1): Encrypt/Decrypt the input plaintext in ECB mode\n");
    printf("  cbc(2): Encrypt/Decrypt the input plaintext in CBC mode\n");
    printf("  ofb(3): Encrypt/Decrypt the input plaintext in OFB mode\n");
    printf("  cfb(4): Encrypt/Decrypt the input plaintext in CFB mode\n");
    printf("  ctr(5): Encrypt/Decrypt the input plaintext in CTR mode\n");
}

int main(int argc, char* argv[]) {
    if (argc != 6) {
        print_usage(argv[0]);
        return 1;
    }
    char *mode = argv[1];
    u8 key[16];

	//copy the content of key
    for (int i = 0; i < 16; i++)
        sscanf(&argv[5][i], "%c", &key[i]); //Implicit conversion in rescue

    if (argv[1][0] == 'e') {
        switch (argv[2][0]) {
        case '1':
            ecb_encrypt(argv[3], argv[4],key);
            break;
        case '2':
            cbc_encrypt(argv[3], argv[4],key);
            break;
        /*case '3':
            ofb_encrypt(argv[3], argv[4],key);
            break;
        case '4':
            cfb_encrypt(argv[3], argv[4],key);
            break;
        default:
            ctr(argv[2], argv[3],key);
            break;*/
        }
    } else {
        switch (argv[2][0]) {
        case '1':
            ecb_decrypt(argv[3], argv[4],key);
            break;
        case '2':
            cbc_decrypt(argv[3], argv[4],key);
            break;
        /*case '3':
            ofb_decrypt(argv[3], argv[4],key);
            break;
        case '4':
            cfb_decrypt(argv[3], argv[4],key);
            break;
        default:
            ctr(argv[2], argv[3],key);
            break;*/
        }
    }
    return 0;
}