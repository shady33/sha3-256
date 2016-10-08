#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "sha3.h"

/* Useful macros */
/* Rotate a 64b word to the left by n positions */
#define ROL64(a, n) ((((n)%64) != 0) ? ((((uint64_t)a) << ((n)%64)) ^ (((uint64_t)a) >> (64-((n)%64)))) : a)
#define BIT(c, i) ((c & (1 << i)) ? 1 : 0)
#define positive_modulo(i,n) (((i%n) + n) % n)

unsigned long concatenate(unsigned char **Z, const unsigned char *X,
              unsigned long X_len, const unsigned char *Y,
              unsigned long Y_len);
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
                 unsigned long X_len);
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m);
unsigned char rc(unsigned int t);

/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
      unsigned int l)
{
    /* The hash size must be one of the supported ones */
    if (s != 224 && s != 256 && s != 384 && s != 512)
        return;

    /* Implement the rest of this function */

    printf("Entering SHA-3\n");
    sponge(m,l);
}

/* Concatenate two bit strings (X||Y)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the first bit string
 * X_len - the length of the first string in bits
 * Y     - the second bit string
 * Y_len - the length of the second string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate(unsigned char **Z, const unsigned char *X,
              unsigned long X_len, const unsigned char *Y,
              unsigned long Y_len)
{
    /* The bit length of Z: the sum of X_len and Y_len */
    unsigned long Z_bit_len = X_len + Y_len;
    /* The byte length of Z:
     * the least multiple of 8 greater than X_len + Y_len */
    unsigned long Z_byte_len = (Z_bit_len / 8) + (Z_bit_len % 8 ? 1 : 0);
    // Allocate the output string and initialize it to 0
    *Z = calloc(Z_byte_len, sizeof(unsigned char));
    if (*Z == NULL)
        return 0;
    // Copy X_len/8 bytes from X to Z
    memcpy(*Z, X, X_len / 8);
    // Copy X_len%8 bits from X to Z
    for (unsigned int i = 0; i < X_len % 8; i++) {
        (*Z)[X_len / 8] |= (X[X_len / 8] & (1 << i));
    }
    // Copy Y_len bits from Y to Z
    unsigned long Z_byte_cursor = X_len / 8, Z_bit_cursor = X_len % 8;
    unsigned long Y_byte_cursor = 0, Y_bit_cursor = 0;
    unsigned int v;
    for (unsigned long i = 0; i < Y_len; i++) {
        // Get the bit
        v = ((Y[Y_byte_cursor] >> Y_bit_cursor) & 1);
        // Set the bit
        (*Z)[Z_byte_cursor] |= (v << Z_bit_cursor);
        // Increment cursors
        if (++Y_bit_cursor == 8) {
            Y_byte_cursor++;
            Y_bit_cursor = 0;
        }
        if (++Z_bit_cursor == 8) {
            Z_byte_cursor++;
            Z_bit_cursor = 0;
        }
    }
    return Z_bit_len;
}

/* Concatenate the 01 bit string to a given bit string (X||01)
 *
 * Z     - the output bit string. The array is allocated by this function: the
 *         caller must take care of freeing it after use.
 * X     - the bit string
 * X_len - the length of the string in bits
 *
 * Returns the length of the output string in bits. The length in Bytes of the
 * output C array is ceiling(output_bit_len/8).
 */
unsigned long concatenate_01(unsigned char **Z, const unsigned char *X,
                 unsigned long X_len)
{
    /* Due to the SHA-3 bit string representation convention, the 01
     * bit string is represented in hexadecimal as 0x02.
     * See Appendix B.1 of the Standard.
     */
    unsigned char zeroone[] = { 0x02 };
    return concatenate(Z, X, X_len, zeroone, 2);
}

/* Performs the pad10*1(x, m) algorithm
 *
 * P - the output bit string. The array is allocated by this function: the
 *     caller must take care of freeing it after use.
 * x - the alignment value
 * m - the existing string length in bits
 *
 * Returns the length in bits of the output bit string.
 */
unsigned long pad10x1(unsigned char **P, unsigned int x, unsigned int m)
{
    /* 1. j = (-m-2) mod x */
    long j = x - ((m + 2) % x);
    /* 2. P = 1 || zeroes(j) || 1 */
    // Compute P bit and byte length
    unsigned long P_bit_len = 2 + j;
    unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
    // Allocate P and initialize to 0
    *P = calloc(P_byte_len, sizeof(unsigned char));
    if (*P == NULL)
        return 0;
    // Set the 1st bit of P to 1
    (*P)[0] |= 1;
    // Set the last bit of P to 1
    (*P)[P_byte_len - 1] |= (1 << (P_bit_len - 1) % 8);

    return P_bit_len;
}

/* Perform the rc(t) algorithm
 *
 * t - the number of rounds to perform in the LFSR
 *
 * Returns a single bit stored as the LSB of an unsigned char.
 */
unsigned char rc(unsigned int t)
{
    unsigned int tmod = t % 255;
    /* 1. If t mod255 = 0, return 1 */
    if (tmod == 0)
        return 1;
    /* 2. Let R = 10000000
     *    The LSB is on the right: R[0] = R &0x80, R[8] = R &1 */
    unsigned char R = 0x80, R0;
    /* 3. For i from 1 to t mod 255 */
    for (unsigned int i = 1; i <= tmod; i++) {
        /* a. R = 0 || R */
        R0 = 0;
        /* b. R[0] ^= R[8] */
        R0 ^= (R & 1);
        /* c. R[4] ^= R[8] */
        R ^= (R & 0x1) << 4;
        /* d. R[5] ^= R[8] */
        R ^= (R & 0x1) << 3;
        /* e. R[6] ^= R[8] */
        R ^= (R & 0x1) << 2;
        /* Shift right by one */
        R >>= 1;
        /* Copy the value of R0 in */
        R ^= R0 << 7;
    }
    /* 4. Return R[0] */
    return R >> 7;
}

/* Perform the theta(A) algorithm
 * A - input state array
 * A' - output state array
 */

void theta( unsigned char a[5][5][64], unsigned char aprime[5][5][64]){
    printf("Entering Theta\n");
    unsigned char c[5][64];
    // C[x,z]=A[x,0,z] ⊕ A[x,1,z] ⊕ A[x,2,z] ⊕ A[x,3,z] ⊕ A[x,4,z]
    for (int i = 0 ; i < 5 ; i++)
        for(int j = 0 ; j < 64 ; j++)
            c[i][j] = a[i][0][j] ^ a[i][1][j] ^ a[i][2][j] ^ a[i][3][j] ^ a[i][4][j];

    unsigned char d[5][64];
    // D[x, z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z –1) mod w].
    for (int i = 0 ; i < 5 ; i++)
        for(int j = 0 ; j < 64 ; j++){
            // printf("%d %d %d ", ((i-1)+5)%5,j,c[((i-1)+5)%5][j]);
            // printf("%d %d %d\n", (i+1)%5,((j-1)+64)%64,c[(i+1)%5][((j-1)+64)%64]);
            d[i][j] = c[((i-1)+5)%5][j] ^ c[(i+1)%5][((j-1)+64)%64];
        }

    //A′[x,y,z] = A[x,y,z] ⊕ D[x,z].
    // unsigned char aprime[5][5][64];
    for (int i = 0 ; i < 5 ; i++)
        for(int j = 0 ; j < 5 ; j++)
            for(int k = 0 ; k < 64 ; k++)
                aprime[i][j][k] = a[i][j][k] ^ d[i][k];
}

/* Perform the p(A) algorithm
 * A - input state array
 * A' - output state array
 */

void rho( unsigned char a[5][5][64], unsigned char aprime[5][5][64]){
    
    //A′ [0,0,z] = A[0,0,z]
    for(int k = 0 ; k < 64  ; k++){
        aprime[0][0][k] = a[0][0][k];
    }

    //Step 3
    int i = 1;
    int j = 0;
    int tmp = 0;
    for ( int t = 0; t < 24 ; t++){
        for(int k = 0 ; k < 64  ; k++){
            aprime[i][j][k] = a[i][j][positive_modulo((k-((t+1)*(t+2)/2)),64)];
        }
        tmp = i;
        i = j;
        j = ((2 * tmp) + (3 * j)) % 5;
    }
}

/* Perform the pi(A) algorithm
 * A - input state array
 * A' - output state array
 */

void pi( unsigned char a[5][5][64], unsigned char aprime[5][5][64]){

    for (int i = 0 ; i < 5 ; i++)
        for(int j = 0 ; j < 5 ; j++)
            for(int k = 0 ; k < 64 ; k++)
                aprime[i][j][k] = a[(i+(3*j))%5][i][k];
}

/* Perform the chi(A) algorithm
 * A - input state array
 * A' - output state array
 */

void chi( unsigned char a[5][5][64] ,unsigned char aprime[5][5][64]){

    for (int i = 0 ; i < 5 ; i++)
        for(int j = 0 ; j < 5 ; j++)
            for(int k = 0 ; k < 64 ; k++)
                aprime[i][j][k] = a[i][j][k] ^ ((a[(i+1)%5][j][k] ^ 1) * a[(i+2)%5][j][k]);
}

/* Perform the iota(A,ir) algorithm
 * A - input/output state array
 * ir - round index
 */

void iota( unsigned char a[5][5][64] , unsigned long ir){
    unsigned int l = 6;
    unsigned char RC[(1<<l)];
    memset(RC,0,sizeof(RC));

    for (int j = 0 ; j < l + 1 ; j++){
        RC[(1<<j)-1] = rc(j + (7 * ir));
        
    }
    for(int k = 0 ; k < 64 ; k++){
        a[0][0][k] = a[0][0][k] ^ RC[k];
    }
}


/* Perform the keccakp(s,b,nr) algorithm
 * s - input string
 * b - string length
 * nr - number of rounds
 * op - output string
 */

unsigned char* keccakp(unsigned char *s , unsigned int b ,unsigned long nr , unsigned char* op){
    
    unsigned char a[5][5][64];
    unsigned char aprime[5][5][64];
    memset(a, 0, sizeof(a));
    memset(aprime, 0, sizeof(aprime));
    string_state(s,a,b);

    for (int ir = 0 ; ir < 24 ; ir++){
        print(a);
        theta(a,aprime);
        printf("THETA\n");
        print(aprime);
        rho(aprime,a);
        printf("RHO\n");
        print(a);
        pi(a,aprime);
        printf("PI\n");
        print(aprime);
        chi(aprime,a);
        printf("CHI\n");
        print(a);
        iota(a,ir);
        printf("IOTA\n");
        print(a);
    }

    state_string(op,a);
}

/* Perform the sponge(A,ir) algorithm
 * n - input string
 * d - non negative integer
 * z - output string
 */

void sponge( unsigned char* m , unsigned int l ){
    unsigned char* op;
    op = (unsigned char*)malloc(201);
    keccakp( m , l ,12 ,op);
    printstring(op);

    unsigned char *P;
    unsigned long p_len;
    unsigned int x = 1088;
    // p_len = pad10x1(P, 1088, l);

    //Moved pad10x1 here
    /* 1. j = (-l-2) mod x */
    long j = x - ((l + 2) % x);
    /* 2. P = 1 || zeroes(j) || 1 */
    // Compute P bit and byte length
    unsigned long P_bit_len = 2 + j;
    unsigned long P_byte_len = (P_bit_len / 8) + (P_bit_len % 8 ? 1 : 0);
    // Allocate P and initialize to 0
    P = malloc(P_byte_len);
    memset(P,0,sizeof(P));
    // Set the 1st bit of P to 1
    *(P+0) |= 1;
    // Set the last bit of P to 1
    *(P + P_byte_len - 1) |= (1 << (P_bit_len - 1) % 8);

}

/* Perform the string to state array
 * z - input state array
 * n - output string
 */

void state_string(unsigned char *n , unsigned char z[5][5][64]){
    printf("Entering State to String:\n");
    int num = 0;
    int cnt = 0;
    for(int j = 0 ; j < 5 ; j++){
        for(int i = 0 ; i < 5 ; i++){
            for(int k = 0 ; k < 64 ; k+=8){
                num = (z[i][j][k] == 1 ? 1 : 0 )<< (k%8);
                num += (z[i][j][k+1] == 1 ? 1 : 0 )<< ((k+1)%8);
                num += (z[i][j][k+2] == 1 ? 1 : 0 )<< ((k+2)%8);
                num += (z[i][j][k+3] == 1 ? 1 : 0 )<< ((k+3)%8);
                num += (z[i][j][k+4] == 1 ? 1 : 0 )<< ((k+4)%8);
                num += (z[i][j][k+5] == 1 ? 1 : 0 )<< ((k+5)%8);
                num += (z[i][j][k+6] == 1 ? 1 : 0 )<< ((k+6)%8);
                num += (z[i][j][k+7] == 1 ? 1 : 0 )<< ((k+7)%8);
                *(n+cnt) = num;
                cnt += 1;
            }
        }
    }
}

/* Perform the string to state array
 * n - input string
 * z - output state array
 */

void string_state(unsigned char *n , unsigned char z[5][5][64],unsigned int size){
    printf("Entering String to State: %d\n",size);
    for(int j = 0 ; j < 5 ; j++){
        for(int i = 0 ; i < 5 ; i++){
            for(int k = 0 ; k < 64 ; k+=8){
                if(((64 * ((5 * j) + i)) + k) < size){
                    z[i][j][k] = BIT(*(n+i+j),0);
                    z[i][j][k+1] = BIT(*(n+i+j),1);
                    z[i][j][k+2] = BIT(*(n+i+j),2);
                    z[i][j][k+3] = BIT(*(n+i+j),3);
                    z[i][j][k+4] = BIT(*(n+i+j),4);
                    z[i][j][k+5] = BIT(*(n+i+j),5);
                    z[i][j][k+6] = BIT(*(n+i+j),6);
                    z[i][j][k+7] = BIT(*(n+i+j),7);
                }
            }
        }
    }
}

void printstring(unsigned char* s){
    printf("Printing String\n");
    for(int i = 0 ; i < 200 ; i++){
        printf("%02x ", *(s+i));
    }
}

void print(unsigned char a[5][5][64]){
    printf("Printing\n");
    int num = 0;
    for(int j = 0 ; j < 5 ; j++)
        for(int i = 0 ; i < 5 ; i++){
            for(int k = 63 ; k > -1 ; k-=8){
                num = (a[i][j][k] == 1 ? 1 : 0 )<< (k%8);
                num += (a[i][j][k-1] == 1 ? 1 : 0 )<< ((k-1)%8);
                num += (a[i][j][k-2] == 1 ? 1 : 0 )<< ((k-2)%8);
                num += (a[i][j][k-3] == 1 ? 1 : 0 )<< ((k-3)%8);
                num += (a[i][j][k-4] == 1 ? 1 : 0 )<< ((k-4)%8);
                num += (a[i][j][k-5] == 1 ? 1 : 0 )<< ((k-5)%8);
                num += (a[i][j][k-6] == 1 ? 1 : 0 )<< ((k-6)%8);
                num += (a[i][j][k-7] == 1 ? 1 : 0 )<< ((k-7)%8);
                printf("%02x", num);
            }
            printf(" ");
        }
}

void print_2d(unsigned char *a, int l, int m){
    printf("Printing 2D\n");
    for(int i = 0 ; i < l ; i++)
        for(int j = 0 ; j < m ; j++){
            if(j%8 == 0)
                printf(" ");
            printf("%d", *(a+i+j));
        }    
}
