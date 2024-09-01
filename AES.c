#include <stdio.h>
#include <stdlib.h> //For Error Handling
#include "utils.h"
#include "moops.h"


void print_usage(char *program_name) {
    printf("Usage: %s <operation> <mode_of_operation> <inputfile> <outputfile> <key>\n", program_name);
    printf("Modes:\n");
    printf("  encrypt(e): Encrypt the input plaintext\n");
    printf("  decrypt(d): Decrypt the input ciphertext\n");
    printf("Modes of confidentiality:\n");
    printf("  (1)Electronic Codebook Mode: Encrypt/Decrypt the input plaintext in ECB mode\n");
    printf("  (2)Cipher Block Chaining Mode: Encrypt/Decrypt the input plaintext in CBC mode\n");
    printf("  (3)Cipher Feedback Mode: Encrypt/Decrypt the input plaintext in CFB mode\n");
    printf("  (4)Output FeedBack Mode: Encrypt/Decrypt the input plaintext in OFB mode\n");
    printf("  (5)Counter Mode: Encrypt/Decrypt the input plaintext in CTR mode\n");
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

    //Generate the expanded key
    u8 ExpandedKey[176];
    KeyExpansion(key, ExpandedKey);

    //Open the respective files
    FILE *ifile = fopen(argv[3], "rb");
    FILE *ofile = fopen(argv[4], "wb");
    // Check if the file opening was successful
    if (ifile==NULL || ofile==NULL) {
        perror("File opening failed");
        exit(EXIT_FAILURE);
    }

    if (argv[1][0] == 'e') {
        switch (argv[2][0]) {
        case '1':
            ecb_encrypt(ifile, ofile, ExpandedKey);
            break;
        case '2':
            cbc_encrypt(ifile, ofile, ExpandedKey);
            break;
        case '3':
            cfb_encrypt(ifile, ofile, ExpandedKey);
            break;
        case '4':
            ofb(ifile, ofile, ExpandedKey, 'e');
            break;
        default:
            ctr(ifile, ofile, ExpandedKey, 'e');
            break;
        }
    } else {
        switch (argv[2][0]) {
        case '1':
            ecb_decrypt(ifile, ofile, ExpandedKey);
            break;
        case '2':
            cbc_decrypt(ifile, ofile, ExpandedKey);
            break;
        case '3':
            cfb_decrypt(ifile, ofile, ExpandedKey);
            break;
        case '4':
            ofb(ifile, ofile, ExpandedKey, 'd');
            break;
        default:
            ctr(ifile, ofile, ExpandedKey,'d');
            break;
        }
    }

    fclose(ifile);
    fclose(ofile);
    return 0;
}
