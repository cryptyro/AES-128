//Inverse of sbox(),
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
/*
    u8 w[176];  // 4*(Nr+1) = 4*11 = 44 words in AES-128
// A variant of KeyExpansion()
u8* KeyExpansionEIC(u8* key) {
    static u8 w[4][44];
    static u8 dw[4][44];
    u8 temp[4];
    int i = 0;
    // Initial key expansion
    while (i < NK) {
        for (int j = 0; j < 4; ++j)
            dw[j][i] = w[j][i] = key[4 * i + j];
        ++i;
    }
    // Main key expansion loop
    while (i < 4*NR + 4) {
        for (int j = 0; j < 4; ++j)
            temp[j] = w[j][i - 1];
        if (i % NK == 0) {
            // Rotate and substitute the bytes, and add the round constant.
            u8 t = temp[0];
            temp[0] = sbox[temp[1]] ^ Rcon[(i/NK)-1];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
        }
        for (int j = 0; j < 4; ++j)
            dw[j][i] = w[j][i] = w[j][i - NK] ^ temp[j];
        ++i;
    }
    // Apply InvMixColumns to the key schedule
    for (int round = 1; round < NR; ++round) {
        i = 4 * round;
        u8 tempo[16];
        // Copy into a 1-D array
        for (int r = 0; r<4; ++r){
            for (int c = 0; c<4; ++c){
                tempo[4*r + c] = dw[r][i + c];
            }
        }
        InvMixColumns(tempo);
        //Store the result into dw
        for (int r = 0; r<4; ++r){
            for (int c = 0; c<4; ++c){
                dw[r][i + c] = tempo[4*r + c];
            }
        }
    }
    return dw;
}

//An equivalent InvCipher for AES decryption on a block of data
void EqInvCipher(u8* input, u8* ExpandedKey) {
    u8 state[16];

    // Copy the input to the state array.
    for (int i = 0; i < 16; ++i)
        state[i] = input[i];

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
    
    // Copy the state array to output.
    for (int i = 0; i < 16; ++i)
        output[i] = state[i];
}*/
