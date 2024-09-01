#ifndef UTILITIES_H
#define UTILITIES_H	

#define NK 4  // Number of 32-bit words in the key (AES-128 has Nk=4)
#define NR 10 // Number of rounds (AES-128 has Nr=10)

typedef unsigned char u8;
void KeyExpansion(u8* key, u8* w);
void Cipher(u8* state, u8* ExpandedKey);
void KeyExpansionEIC(u8* key, u8* dw);
void InvCipher( u8* state, u8* ExpandedKey);
void EqInvCipher(u8* state, u8* ExpandedKey);

#endif
