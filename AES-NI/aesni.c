#include <time.h>
#include <wmmintrin.h>
#include <stdio.h>
#define NUM_LOOPS 10000000

typedef unsigned char u8;
__m128i AES_128_ASSIST (__m128i temp1, __m128i temp2)
{
__m128i temp3;
temp2 = _mm_shuffle_epi32 (temp2 ,0xff);
temp3 = _mm_slli_si128 (temp1, 0x4);
temp1 = _mm_xor_si128 (temp1, temp3);
temp3 = _mm_slli_si128 (temp3, 0x4);
temp1 = _mm_xor_si128 (temp1, temp3);
temp3 = _mm_slli_si128 (temp3, 0x4);
temp1 = _mm_xor_si128 (temp1, temp3);
temp1 = _mm_xor_si128 (temp1, temp2);
return temp1;
}
void AES_128_Key_Expansion (const u8 *userkey, u8 *expkey, u8 *expkeyEIC)
{
__m128i temp;
__m128i *Key_Schedule = (__m128i*)expkey;
__m128i *EICKey_Schedule = (__m128i*)expkeyEIC;
Key_Schedule[0] = EICKey_Schedule[0] = _mm_loadu_si128((__m128i*)userkey);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[0] ,0x1);
Key_Schedule[1] =  AES_128_ASSIST(Key_Schedule[0], temp);
EICKey_Schedule[1] = _mm_aesimc_si128(Key_Schedule[1]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[1],0x2);
Key_Schedule[2] =  AES_128_ASSIST(Key_Schedule[1], temp);
EICKey_Schedule[2] = _mm_aesimc_si128(Key_Schedule[2]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[2],0x4);
Key_Schedule[3] =  AES_128_ASSIST(Key_Schedule[2], temp);
EICKey_Schedule[3] = _mm_aesimc_si128(Key_Schedule[3]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[3],0x8);
Key_Schedule[4] =  AES_128_ASSIST(Key_Schedule[3], temp);
EICKey_Schedule[4] = _mm_aesimc_si128(Key_Schedule[4]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[4],0x10);
Key_Schedule[5] =  AES_128_ASSIST(Key_Schedule[4], temp);
EICKey_Schedule[5] = _mm_aesimc_si128(Key_Schedule[5]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[5],0x20);
Key_Schedule[6] =  AES_128_ASSIST(Key_Schedule[5], temp);
EICKey_Schedule[6] = _mm_aesimc_si128(Key_Schedule[6]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[6],0x40);
Key_Schedule[7] =  AES_128_ASSIST(Key_Schedule[6], temp);
EICKey_Schedule[7] = _mm_aesimc_si128(Key_Schedule[7]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[7],0x80);
Key_Schedule[8] =  AES_128_ASSIST(Key_Schedule[7], temp);
EICKey_Schedule[8] = _mm_aesimc_si128(Key_Schedule[8]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[8],0x1b);
Key_Schedule[9] =  AES_128_ASSIST(Key_Schedule[8], temp);
EICKey_Schedule[9] = _mm_aesimc_si128(Key_Schedule[9]);

temp = _mm_aeskeygenassist_si128 (Key_Schedule[9],0x36);
EICKey_Schedule[10] = Key_Schedule[10] = AES_128_ASSIST(Key_Schedule[9], temp);
}

// Encryption with AES-NI
void encrypt(u8* input, u8* ExpandedKey) {
    // Load the input block into an __m128i register
    __m128i tmp = _mm_loadu_si128 (&((__m128i*)input)[0]);
    
    // Initial XOR with the encryption key (AddRoundKey step)
    tmp = _mm_xor_si128 (tmp,((__m128i*)ExpandedKey)[0]);
    
    // Perform 9 rounds of AES encryption
    for(int j=1; j < 10; j++)
        tmp = _mm_aesenc_si128 (tmp,((__m128i*)ExpandedKey)[j]);
    
    // Perform the final round of AES encryption
    tmp = _mm_aesenclast_si128 (tmp,((__m128i*)ExpandedKey)[10]);
    
    // Store the result back to the input block
    _mm_storeu_si128 (&((__m128i*)input)[0],tmp);
}

// Decryption with AES-NI
void decrypt(u8* input, u8* ExpandedKeyEIC) {
    // Load the input block into an __m128i register
    __m128i tmp = _mm_loadu_si128(&((__m128i*)input)[0]);

    // Initial XOR with the last round key (Inverse AddRoundKey step)
    tmp = _mm_xor_si128(tmp, ((__m128i*)ExpandedKeyEIC)[10]);

    // Perform 9 rounds of AES decryption
    for (int j = 9; j > 0; j--)
        tmp = _mm_aesdec_si128(tmp, ((__m128i*)ExpandedKeyEIC)[j]);

    // Perform the final round of AES decryption
    tmp = _mm_aesdeclast_si128 (tmp,((__m128i*)ExpandedKeyEIC)[0]);

    // Store the result back to the input block
    _mm_storeu_si128 (&((__m128i*)input)[0],tmp);
}

int main(){
    // Test Vector
    u8 input[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    const u8 key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    u8 ExpandedKey[176], ExpandedKeyEIC[176];
    AES_128_Key_Expansion(key, ExpandedKey, ExpandedKeyEIC);
    
    /*for (size_t i = 0; i < 44; i++){
        for (size_t j = 0; j < 4; j++)        
            printf("%02x ", ExpandedKey[4*i+j]);
        printf("\n");
    }
    printf("\n");
    for (size_t i = 0; i < 44; i++){
        for (size_t j = 0; j < 4; j++)        
            printf("%02x ", ExpandedKeyEIC[4*i+j]);
        printf("\n");
    }*/
    
    // Performance check
    clock_t start_time = clock();
    for(int i=0; i < NUM_LOOPS; i++){
		encrypt(input, ExpandedKey) ;
		decrypt(input, ExpandedKeyEIC) ;
	}
    clock_t end_time = clock();
    double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("Execution time: %f seconds\n", time_taken);
    for (int i=0 ; i <16 ; i++)
    	printf(" %x",input[i]);
    return 0;
}
