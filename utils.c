#include <emmintrin.h> //For SIMD Extensions 2 
#include "utils.h"

// AES S-box
const u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

//Inverse S-box(),
const u8 InvSbox[256]  = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
    

// AES round constants
const u8 Rcon[10] = 
{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

/* Function to perform the SubBytes operation in the AES encryption algorithm */
void SubBytes(u8* state) {
	// Replace each byte with its corresponding value from the S-box
    state[0]  = sbox[state[0]];
    state[1]  = sbox[state[1]];
    state[2]  = sbox[state[2]];
    state[3]  = sbox[state[3]];
    state[4]  = sbox[state[4]];
    state[5]  = sbox[state[5]];
    state[6]  = sbox[state[6]];
    state[7]  = sbox[state[7]];
    state[8]  = sbox[state[8]];
    state[9]  = sbox[state[9]];
    state[10] = sbox[state[10]];
    state[11] = sbox[state[11]];
    state[12] = sbox[state[12]];
    state[13] = sbox[state[13]];
    state[14] = sbox[state[14]];
    state[15] = sbox[state[15]];
}

// InvSubBytes applies the inverse S-box to each byte of the state
void InvSubBytes(u8* state) {
	// Replace each byte with its corresponding value from the Inverse S-box
    state[0]  = InvSbox[state[0]];
    state[1]  = InvSbox[state[1]];
    state[2]  = InvSbox[state[2]];
    state[3]  = InvSbox[state[3]];
    state[4]  = InvSbox[state[4]];
    state[5]  = InvSbox[state[5]];
    state[6]  = InvSbox[state[6]];
    state[7]  = InvSbox[state[7]];
    state[8]  = InvSbox[state[8]];
    state[9]  = InvSbox[state[9]];
    state[10] = InvSbox[state[10]];
    state[11] = InvSbox[state[11]];
    state[12] = InvSbox[state[12]];
    state[13] = InvSbox[state[13]];
    state[14] = InvSbox[state[14]];
    state[15] = InvSbox[state[15]];
}

/* Function to perform the ShiftRows step in the AES encryption algorithm */
void ShiftRows(u8* state) {
    // Shift second row
    u8 temp = state[1];
    state[1]  = state[5];
    state[5]  = state[9];
    state[9]  = state[13];
    state[13] = temp;

    // Shift third row
    temp = state[2];
    state[2]  = state[10];
    state[10] = temp;
    temp = state[6];
    state[6]  = state[14];
    state[14] = temp;

    // Shift fourth row
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7]  = state[3];
    state[3]  = temp;
}

/* Function to perform the InvShiftRows step in the AES encryption algorithm */
void InvShiftRows(u8* state) {
    // Shift back second row
    u8 temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // Shift back third row
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // Shift back fourth row
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// xtime function: multiplies by 0x02 in GF(2^8)
u8 xtime(u8 b) {
	return (b << 1) ^ ((b >> 7) * 0x1B);
}

/* Function to perform the MixColumns operation in the AES encryption algorithm */
void MixColumns(u8* s) {    
	// Mix first column
    u8 t = s[0] ^ s[1] ^ s[2] ^ s[3];
    u8 temp = s[0];
    s[0] ^= xtime(s[0] ^ s[1]) ^ t;
    s[1] ^= xtime(s[1] ^ s[2]) ^ t;
    s[2] ^= xtime(s[2] ^ s[3]) ^ t;
    s[3] ^= xtime(s[3] ^ temp) ^ t;
    
    // Mix second column
    t = s[4] ^ s[5] ^ s[6] ^ s[7];
    temp = s[4];
    s[4] ^= xtime(s[4] ^ s[5]) ^ t;
    s[5] ^= xtime(s[5] ^ s[6]) ^ t;
    s[6] ^= xtime(s[6] ^ s[7]) ^ t;
    s[7] ^= xtime(s[7] ^ temp) ^ t;
    
    // Mix third column
    t = s[8] ^ s[9] ^ s[10] ^ s[11];
    temp  = s[8];
    s[8]  ^= xtime(s[8]  ^ s[9])  ^ t;
    s[9]  ^= xtime(s[9]  ^ s[10]) ^ t;
    s[10] ^= xtime(s[10] ^ s[11]) ^ t;
    s[11] ^= xtime(s[11] ^ temp)  ^ t;
    
    // Mix fourth column
    t = s[12] ^ s[13] ^ s[14] ^ s[15];
    temp = s[12];
    s[12] ^= xtime(s[12] ^ s[13]) ^ t;
    s[13] ^= xtime(s[13] ^ s[14]) ^ t;
    s[14] ^= xtime(s[14] ^ s[15]) ^ t;
    s[15] ^= xtime(s[15] ^ temp)  ^ t;
}

// InvMixColumns transforms the columns of the state
void InvMixColumns(u8* s) {
    u8 u = xtime(xtime(s[0] ^ s[2]));
    u8 v = xtime(xtime(s[1] ^ s[3]));
    s[0] ^= u;
    s[1] ^= v;
    s[2] ^= u;
    s[3] ^= v;
    
    u = xtime(xtime(s[4] ^ s[6]));
    v = xtime(xtime(s[5] ^ s[7]));
    s[4] ^= u;
    s[5] ^= v;
    s[6] ^= u;
    s[7] ^= v;
    
    u = xtime(xtime(s[8] ^ s[10]));
    v = xtime(xtime(s[9] ^ s[11]));
    s[8]  ^= u;
    s[9]  ^= v;
    s[10] ^= u;
    s[11] ^= v;
    
    u = xtime(xtime(s[12] ^ s[14]));
    v = xtime(xtime(s[13] ^ s[15]));
    s[12] ^= u;
    s[13] ^= v;
    s[14] ^= u;
    s[15] ^= v;

    MixColumns(s);
}

void AddRoundKey(u8* state, u8* ExpandedKey, u8 round) {
    // Load 16 bytes from the state and the corresponding round key
    __m128i* stateVec = (__m128i*)state;
    __m128i* roundKeyVec = (__m128i*)(ExpandedKey + 16 * round);

    // Perform the XOR operation for 16 bytes at once
    *stateVec = _mm_xor_si128(*stateVec, *roundKeyVec);
}

//AES-128 key expansion function
void KeyExpansion(u8* key, u8* w) {
    u8 temp[4];

    // Copy the initial key into the first Nk words of the expanded key
    for (int j = 0; j < 16; ++j)
        w[j] = key[j];

    // All other round keys are found from the previous round keys.
    for (int i = NK; i < 4 * (NR + 1); ++i) {
        // Copy the previous word into temp
        temp[0] = w[4*(i-1)];
        temp[1] = w[4*(i-1) + 1];
        temp[2] = w[4*(i-1) + 2];
        temp[3] = w[4*(i-1) + 3];

        // Apply transformations if at the start of a round
        if (i % NK == 0) {
            // Rotate the bytes in temp
            u8 t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[(i/NK) - 1];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }

        // XOR with the word NK positions earlier
        w[4*i]     = w[4*(i-NK)]     ^ temp[0];
        w[4*i + 1] = w[4*(i-NK) + 1] ^ temp[1];
        w[4*i + 2] = w[4*(i-NK) + 2] ^ temp[2];
        w[4*i + 3] = w[4*(i-NK) + 3] ^ temp[3];
    }
}

// A variant of KeyExpansion()
void KeyExpansionEIC(u8* key, u8* dw) {
    u8 w[176], temp[4];

    // Copy the initial key into the first Nk words of the expanded key
    for (int j = 0; j < 16; ++j)
        dw[j] = w[j] = key[j];
    
    // Main key expansion loop
    for (u8 i = NK; i < 4 * (NR + 1); ++i) {
        // Copy the previous word into temp
        temp[0] = w[4*(i-1)];
        temp[1] = w[4*(i-1) + 1];
        temp[2] = w[4*(i-1) + 2];
        temp[3] = w[4*(i-1) + 3];

        // Apply transformations if at the start of a round
        if (i % NK == 0) {
            // Rotate the bytes in temp
            u8 t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[(i/NK) - 1];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }

        // XOR with the word NK positions earlier
        dw[4*i]     = w[4*i]     = w[4*(i-NK)]     ^ temp[0];
        dw[4*i + 1] = w[4*i + 1] = w[4*(i-NK) + 1] ^ temp[1];
        dw[4*i + 2] = w[4*i + 2] = w[4*(i-NK) + 2] ^ temp[2];
        dw[4*i + 3] = w[4*i + 3] = w[4*(i-NK) + 3] ^ temp[3];
    }
    // Apply InvMixColumns to the key schedule
    for (int round = 1; round < NR; ++round) {
        int i = 16 * round;
        InvMixColumns(dw+i);
    }
}

/* The AES encryption function that operates on 16 byte block */
void Cipher(u8* state, u8* ExpandedKey) {
    // Initial round key addition.
    AddRoundKey(state, ExpandedKey, 0);

    // 9 main rounds.
    for (u8 round = 1; round < NR; ++round) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, ExpandedKey, round);
    }

    // Final round (no MixColumns).
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, ExpandedKey, 10);
}

// InvCipher performs AES decryption on a block of data
void InvCipher( u8* state, u8* ExpandedKey) {
    AddRoundKey(state, ExpandedKey, 10);

    for (u8 round = NR-1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, ExpandedKey, round);
        InvMixColumns(state);
    }

    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, ExpandedKey, 0);
}

//An equivalent InvCipher for AES decryption on a block of data
void EqInvCipher(u8* state, u8* ExpandedKey) {
    AddRoundKey(state, ExpandedKey, 10);

    for (u8 round = NR-1; round > 0; round--) {
        InvSubBytes(state);
        InvShiftRows(state);
        InvMixColumns(state);
        AddRoundKey(state, ExpandedKey, round);
    }

    InvSubBytes(state);
    InvShiftRows(state);
    AddRoundKey(state, ExpandedKey, 0);
}