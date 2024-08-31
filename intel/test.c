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
void AES_128_Key_Expansion (const u8 *userkey, u8 *key)
{
__m128i temp1, temp2;
__m128i *Key_Schedule = (__m128i*)key;
temp1 = _mm_loadu_si128((__m128i*)userkey);
Key_Schedule[0] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1 ,0x1);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[1] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x2);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[2] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x4);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[3] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x8);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[4] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x10);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[5] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x20);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[6] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x40);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[7] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x80);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[8] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x1b);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[9] = temp1;
temp2 = _mm_aeskeygenassist_si128 (temp1,0x36);
temp1 = AES_128_ASSIST(temp1, temp2);
Key_Schedule[10] = temp1;
}

int main(){
    // Test Vector
    u8 input[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
    const u8 key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    u8 ExpandedKey[176];
    AES_128_Key_Expansion(key, ExpandedKey);
    for (size_t i = 0; i < 44; i++){
        for (size_t j = 0; j < 4; j++)        
            printf("%02x ", ExpandedKey[4*i+j]);
        printf("\n");
    }
    __m128i tmp;
    clock_t start_time = clock();
    int i,j;
    for(i=0; i < NUM_LOOPS; i++){
        tmp = _mm_loadu_si128 (&((__m128i*)input)[0]);
        tmp = _mm_xor_si128 (tmp,((__m128i*)key)[0]);
        for(j=1; j < 10; j++){
            tmp = _mm_aesenc_si128 (tmp,((__m128i*)ExpandedKey)[j]);
        }
        tmp = _mm_aesenclast_si128 (tmp,((__m128i*)ExpandedKey)[10]);
        _mm_storeu_si128 (&((__m128i*)input)[0],tmp);
    }
    clock_t end_time = clock();
    
    double time_taken = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

    printf("Execution time: %f seconds\n", time_taken);
    
    for (int i = 0; i < 16; ++i)
        printf("%02x ", input[i]);
    return 0;
}
