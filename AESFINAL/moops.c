#include <stdio.h>
#include <stdlib.h> //For Error Handling
#include <openssl/rand.h> //For Random IV Generation
#include <unistd.h>  // For ftruncate on POSIX systems
#include <emmintrin.h> //For SIMD Extensions 2 
#include "moops.h"
#include "utils.h"

// Declare a global IV of size 16 bytes (128 bits)
unsigned char IV[16];

// Generate random bytes for the IV
void generate_iv() {
    if (!RAND_bytes(IV, sizeof(IV))) {
        perror("Error generating random IV");
        exit(EXIT_FAILURE);
    }
}

// XOR two 16 byte array
void xor(u8* a, u8* b){
    __m128i* Veca = (__m128i*)a;
    __m128i* Vecb = (__m128i*)b;
    *Veca = _mm_xor_si128(*Veca, *Vecb);
}

// Function to handle PKCS#7 unpadding
u8 pkcs7_unpad(u8* plaintext) {
    u8 pad_value = plaintext[15];
    if (pad_value > 0 && pad_value <= 16) {
        for (u8 i = 0; i < pad_value; ++i) {
            if (plaintext[16 - 1 - i] != pad_value) {
                fprintf(stderr, "Invalid PKCS#7 padding\n");
                exit(EXIT_FAILURE);
            }
        }
        return pad_value;
    } else {
        fprintf(stderr, "Invalid PKCS#7 padding\n");
        exit(EXIT_FAILURE);
    }
}

void ecb_encrypt(FILE* ifile, FILE *ofile, u8* ExpandedKey){
    u8 in_block[16];
    u8 bytes_read;

    // Read the input file in 16-byte chunks, encrypt, and write to output file
     while ((bytes_read = fread(in_block, 1, 16, ifile)) == 16) {
        Cipher(in_block, ExpandedKey);
        fwrite(in_block, 1, 16, ofile);
    }

    // Apply PKCS#7 padding
    u8 padding_value = 16 - bytes_read;
    for (u8 i = bytes_read; i < 16; ++i)
        in_block[i] = padding_value;
    Cipher(in_block, ExpandedKey);
    fwrite(in_block, 1, 16, ofile);
}

void ecb_decrypt(FILE* ifile, FILE *ofile, u8* ExpandedKey){
    u8 in_block[16], out_block[16];
    u8 bytes_read;

    // Read the input file in 16-byte chunks, decrypt, and write to output file
    while (fread(in_block, 1, 16, ifile) > 0) {
        InvCipher(in_block, ExpandedKey);
        fwrite(in_block, 1, 16, ofile);
    }
    // Handle the last block with padding removal
    u8 pad_len = pkcs7_unpad(in_block);
    fseek(ofile, -pad_len,SEEK_END);
    // Get the current position in the file
    long current_pos = ftell(ofile);
     // Truncate the file to the new size
    ftruncate(fileno(ofile), current_pos);
}

void cbc_encrypt(FILE* ifile, FILE *ofile, u8* ExpandedKey){
    u8 plaintext[16];
    u8 bytes_read;
    generate_iv();
    // Write the IV to the outfile first
    fwrite(IV, 1, 16, ofile);

    // Read from the file by 16 bytes and operate on CBC mode
    while ((bytes_read = fread(plaintext, 1, 16, ifile)) == 16) {
        //XOR plaintext with the IV
        for (u8 i = 0; i < 16; ++i)
            IV[i] ^= plaintext[i] ; 
        
        Cipher(IV, ExpandedKey);
        // Write the encrypted plaintext to the output file
        fwrite(IV, 1, 16, ofile);
    }

    // PKSC#7 padding
    u8 padding_value = 16 - bytes_read;
    // Fill the remaining part with the padding value
    for (u8 i = bytes_read; i < 16; ++i)
        plaintext[i] = padding_value;
    //XOR plaintext with the IV
    for (u8 i = 0; i < 16; ++i)
        IV[i] ^= plaintext[i] ; 
    Cipher(IV, ExpandedKey);
    fwrite(IV, 1, 16, ofile);
}

void cbc_decrypt(FILE* ifile, FILE *ofile, u8* ExpandedKey){
    u8 input[16], temp[16], output[16];
    u8 bytes_read;

    // Get the IV first
    fread(IV, 1, 16, ifile);
    
    // Read from the file by 16 bytes and operate on CBC decryption mode
    while (fread(input, 1, 16, ifile) > 0) {
        for (u8 i = 0; i < 16; i++)
            temp[i] = input[i];
        
        InvCipher(input, ExpandedKey);
        //XOR plaintext with the IV
        for (u8 i = 0; i < 16; ++i)
            input[i] ^= IV[i];// Get the original plaintext
        
        for (u8 i = 0; i < 16; i++)
            IV[i] = temp[i];

        fwrite(input, 1, 16, ofile);
    }

    //Get the last plaintext of the input and validate PKCS padding
    u8 pad_len = pkcs7_unpad(input);
    fseek(ofile, -pad_len,SEEK_END);
    // Get the current position in the file
    long current_pos = ftell(ofile);
     // Truncate the file to the new size
    ftruncate(fileno(ofile), current_pos);
}

void cfb_encrypt(FILE* ifile, FILE *ofile, u8* ExpandedKey){
    u8 in_block[16];
    u8 bytes_read;
    generate_iv();
    // Write the IV to the outfile first
    fwrite(IV, 1, 16, ofile);

    // Read from the file by 16 bytes and operate on CFB mode
    while ((bytes_read = fread(in_block, 1, 16, ifile)) > 0) {
        Cipher(IV, ExpandedKey);
        //XOR plaintext with the IV
        xor(IV, in_block);
        
        // Write the encrypted plaintext to the output file
        fwrite(IV, 1, bytes_read, ofile);
    }
}

void cfb_decrypt(FILE* ifile, FILE *ofile, u8* ExpandedKey){
    u8 in_block[16];
    u8 bytes_read;

    // Write the IV to the outfile first
    fread(IV, 1, 16, ifile);

    // Read from the file by 16 bytes and operate on CFB mode
    while ((bytes_read = fread(in_block, 1, 16, ifile)) > 0) {
        Cipher(IV, ExpandedKey);
        xor(IV,in_block); //XOR plaintext with the IV
        fwrite(IV, 1, 16, ofile);// Write the decrypted plaintext to the output file

        //Get the ciphertext as IV for next block
        for (u8 i = 0; i < 16; i++)
            IV[i] = in_block[i];
    }
}

void ofb(FILE* ifile, FILE *ofile, u8* ExpandedKey, char choice){
    u8 in_block[16];
    u8 bytes_read;
    generate_iv();

    if(choice == 'e') fwrite(IV, 1, 16, ofile);// Write the IV to the outfile
    else fread(IV, 1, 16, ifile);// Read the IV from the inputfile
    
    // Read from the file by 16 bytes and operate on OFB mode
    while ((bytes_read = fread(in_block, 1, 16, ifile)) > 0) {
        Cipher(IV, ExpandedKey);
        xor(in_block,IV); //XOR input with the output from encryption block
        
        // Write the encrypted plaintext to the output file
        fwrite(in_block, 1, bytes_read, ofile);
    }
}

void ctr(FILE *ifile, FILE *ofile, u8* ExpandedKey, char choice){
    generate_iv();
    
    if(choice == 'e') fwrite(IV, 1, 16, ofile);// Write the IV to the outfile
    else fread(IV, 1, 16, ifile);// Read the IV from the inputfile

    //Set the least significant 32 bits to 0
    IV[0]=IV[1]=IV[2]=IV[3]=0x00;

    u8 input[16], in_block[16];
    u8 bytes_read;

    // Read the input file in 16-byte chunks, encrypt, and write to output file
    while ((bytes_read = fread(in_block, 1, 16, ifile)) > 0) {
        for (u8 i = 0; i < 16; i++)
            input[i]=IV[i];
        
        Cipher(input,ExpandedKey);
        xor(input, in_block);
        fwrite(in_block, 1, bytes_read, ofile);
        // Increament least sinificant 32 bits
        for (u8 i = 0; i < 4; ++i)
            if (++IV[i] != 0) break;
    }
}
