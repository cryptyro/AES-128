#include <stdlib.h> //For Error Handling
#include <openssl/rand.h> //For Random IV Generation
#include <unistd.h>  // For ftruncate on POSIX systems

// Function to handle PKCS#7 unpadding
u8 pkcs7_unpad(u8* plaintext) {
    u8 pad_value = plaintext[16 - 1];
    if (pad_value > 0 && pad_value <= 16) {
        for (size_t i = 0; i < pad_value; ++i) {
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

void ecb_encrypt(const char* infilename, const char *outfilename, u8* Key){
    FILE *ifile = fopen(infilename, "rb");
    FILE *ofile = fopen(outfilename, "wb");
    if (ifile==NULL || ofile==NULL) {
        perror("File opening failed");
        exit(EXIT_FAILURE);
    }

    u8 in_block[16];
    size_t bytes_read;

	//Generate the expanded key
    u8 ExpandedKey[176];
    KeyExpansion(Key, ExpandedKey);

    // Read the input file in 16-byte chunks, encrypt, and write to output file
     while ((bytes_read = fread(in_block, 1, 16, ifile)) == 16) {
        Cipher(in_block, ExpandedKey);
        fwrite(in_block, 1, 16, ofile);
    }

    // If the last read block is less than 16 bytes, apply PKCS#7 padding
    if (bytes_read > 0 && bytes_read < 16) {
        u8 padding_value = 16 - bytes_read;
        for (size_t i = bytes_read; i < 16; ++i) {
            in_block[i] = padding_value;
        }
        Cipher(in_block, ExpandedKey);
        fwrite(in_block, 1, 16, ofile);
    }

    // If the file size is an exact multiple of 16, add an extra block of padding
    if (bytes_read == 0 && feof(ifile)) {
        u8 padding_block[16];
        for (size_t i = 0; i < 16; ++i) {
            padding_block[i] = 0x10;  // 0x10 indicates 16 bytes of padding
        }
        Cipher(padding_block, ExpandedKey);
        fwrite(padding_block, 1, 16, ofile);
    }

    fclose(ifile);
    fclose(ofile);
}

void ecb_decrypt(const char* infilename, const char* outfilename, u8* Key){
    FILE *ifile = fopen(infilename, "rb");
    FILE *ofile = fopen(outfilename, "wb");
    if (ifile==NULL || ofile==NULL) {
        perror("File opening failed");
        exit(EXIT_FAILURE);
    }

    u8 in_block[16], out_block[16];
    u8 bytes_read;
    //Generate the expanded key
    u8 ExpandedKey[176];
    KeyExpansion(Key, ExpandedKey);

    // Read the input file in 16-byte chunks, encrypt, and write to output file
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

    fclose(ifile);
    fclose(ofile);
}

void cbc_encrypt(const char* infilename,const char* outfilename,u8* Key){
    FILE *ifile = fopen(infilename, "rb");
    FILE *ofile = fopen(outfilename, "wb");

    // Check if the file opening was successful
    if (ifile == NULL || ofile == NULL) {
        perror("File opening failed\n");
        exit(EXIT_FAILURE);
    }

    u8 plaintext[16], IV[16];
    u8 bytes_read = 0;

    // Generate random bytes for the IV
    if (!RAND_bytes(IV, 16)) {
        perror("Error generating random IV\n");
        exit(EXIT_FAILURE);
    }
    // Write the IV to the outfile first
    fwrite(IV, 1, 16, ofile);

    u8 ExpandedKey[176];
    KeyExpansion(Key, ExpandedKey);

    // Read from the file by 16 bytes and operate on CBC mode
    while ((bytes_read = fread(plaintext, 1, 16, ifile)) == 16) {
        //XOR plaintext with the IV
        for (size_t i = 0; i < 16; ++i)
            IV[i] ^= plaintext[i] ; 
        
        Cipher(IV, ExpandedKey);
        // Write the encrypted plaintext to the output file
        fwrite(IV, 1, 16, ofile);
    }

    // PKSC#7 padding
    if (bytes_read > 0 && bytes_read < 16) {
        u8 padding_value = 16 - bytes_read;
        // Fill the remaining part with the padding value
        for (size_t i = bytes_read; i < 16; ++i)
            plaintext[i] = padding_value;
        //XOR plaintext with the IV
        for (size_t i = 0; i < 16; ++i)
            IV[i] ^= plaintext[i] ; 
        Cipher(IV, ExpandedKey);
        fwrite(IV, 1, 16, ofile);
    }

    // Padding for the Edge case
    if (bytes_read == 0 && feof(ifile)) {
        for (size_t i = 0; i < 16; ++i)
            IV[i] ^= 0x10;
        Cipher(IV ,ExpandedKey);
        fwrite(IV, 1, 16, ofile);
    }

    fclose(ifile);
    fclose(ofile);
}

void cbc_decrypt(const char* infilename,const char* outfilename,u8* Key){
    FILE *ifile = fopen(infilename, "rb");
    FILE *ofile = fopen(outfilename, "wb");

    if (ifile == NULL || ofile == NULL) {
        perror("File opening failed");
        exit(EXIT_FAILURE);
    }

    u8 input[16], IV[16], temp[16], output[16];
    size_t bytes_read;

    u8 ExpandedKey[176];
    KeyExpansion(Key, ExpandedKey);

    // Get the IV first
    fread(IV, 1, 16, ifile);
    // Read from the file by 16 bytes and operate on CBC decryption mode
    
    while (fread(input, 1, 16, ifile) > 0) {
        for (size_t i = 0; i < 16; i++)
            temp[i] = input[i];
        
        InvCipher(input, ExpandedKey);
        //XOR plaintext with the IV
        for (size_t i = 0; i < 16; ++i)
            input[i] ^= IV[i];// Get the original plaintext
        
        for (size_t i = 0; i < 16; i++)
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

    fclose(ifile);
    fclose(ofile);
}