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
#define index(x,y) ((( 5 * (y % 5))+ (x % 5)))

uint64_t RC[24] = {0x0000000000000001,0x0000000000008082,0x800000000000808A,0x8000000080008000,0x000000000000808B,0x0000000080000001,0x8000000080008081,0x8000000000008009,0x000000000000008A,0x0000000000000088,0x0000000080008009,0x000000008000000A,0x000000008000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x000000000000800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x0000000080000001,0x8000000080008008};
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
    unsigned char *input;
    unsigned long length;

    // Concatenate Message with 01 i.e. input = M || 01
    length = concatenate_01(&input,m,l);

    // Sponge function
    sponge(d,s,input,length);
    free(input);
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
 * a - input state array
 * aprime - output state array
 */
void theta( uint64_t *a )
{
    uint64_t c[5] , d[5];
    for ( unsigned int i = 0 ; i < 5 ; i++)
    {
        c[i] =  *(a+index(i,0)) ^ *(a+index(i,1)) ^ *(a+index(i,2)) ^ *(a+index(i,3)) ^ *(a+index(i,4));
    }

    for ( unsigned int i = 0 ; i < 5 ; i++)
    {
        d[i] = c[((i-1)+5)%5] ^ ROL64(c[(i+1)%5],1);
    }

    for ( unsigned int i = 0 ; i < 5 ; i++)
    {   
        for ( unsigned int j = 0 ; j < 5 ; j++)
        {
            *(a + index(i,j)) = *(a + index(i,j)) ^ d[i];
        }
    }
}

/* Perform the p(A) algorithm
 * a - input state array
 * aprime - output state array
 */
void rho( uint64_t *a )
{    
    /* For t from 0 to 23:
     *   a. for all z such that 0≤z<w, let A′[x, y, z] = A[x, y, (z–(t+1)(t+2)/2) mod w];
     *   b. let (x, y) = (y, (2x+3y) mod 5).
     */
    int i = 1;
    int j = 0;
    int tmp = 0;
    for ( int t = 0; t < 24 ; t++)
    {
        *(a + index(i,j)) = ROL64(*(a + index(i,j)),((t+1)*(t+2))/2);
        tmp = i;
        i = j;
        j = ((2 * tmp) + (3 * j)) % 5;
    }
}

/* Perform the pi(A) algorithm
 * a - input state array
 * aprime - output state array
 */
void pi( uint64_t *a )
{
    uint64_t *b;
    b = malloc(200);
    memset(b,0,sizeof(b));

    // For all x,y,z -> A′[x, y, z]= A[(x + 3y) mod 5, x, z].
    for (int i = 0 ; i < 5 ; i++)
    {
        for(int j = 0 ; j < 5 ; j++)
        {
            *(b + index(i,j)) = *(a + index((i+(3*j))%5,i));
        }
    }
    memcpy(a,b,200);
    free(b);
}

/* Perform the chi(A) algorithm
 * A - input state array
 * A' - output state array
 */
void chi( uint64_t *a)
{
    uint64_t *b;
    uint64_t tmp;
    b = malloc(200);
    memset(b,0,sizeof(b));

    // For all x,y,z -> A′[x,y,z] = A[x,y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
    for (int i = 0 ; i < 5 ; i++)
    {
        for(int j = 0 ; j < 5 ; j++)
        {
            tmp = (*(a + index((i+1)%5,j)) ^ 0xFFFFFFFFFFFFFFFF) & (*(a + index((i+2)%5,j)));
            *(b + index(i,j)) = *(a + index(i,j)) ^ tmp;
        }
    }
    memcpy(a,b,200);
    free(b);
}

/* Perform the iota(A,ir) algorithm
 * a - input/output state array
 * ir - round index
 */
void iota( uint64_t *a , unsigned long ir)
{
    // a[0,0,z]=a[0,0,z] ⊕ RC[ir].
    *( a + index(0,0))= *( a + index(0,0))^ RC[ir];
}

/* Perform the keccakp(s,b,nr) algorithm
 * s - input string
 * b - string length
 * nr - number of rounds
 * op - output string
 */
void keccakp(unsigned char *s , unsigned int b ,unsigned long nr , unsigned char* op)
{
    uint64_t *a;
    a = s;
    // printstring(s,b);


    // for(unsigned int i = 0 ; i < (b/64) ; i++)
    //     printf("%016" PRIx64 " ", *(a+i));

    // unsigned char a[5][5][64];
    // unsigned char aprime[5][5][64];
    // memset(a, 0, sizeof(a));
    // memset(aprime, 0, sizeof(aprime));

    // // String to State Array a
    // string_state(s,a,b);

    // 12+2l–nr to 12+2l-1 ... l = 6 and nr = 24
    for (unsigned int ir = 0 ; ir < nr ; ir++)
    {
        theta(a);
        // printf("Theta\n");
        // printstring(a,1600);

        rho(a);
        // printf("\nRho\n");
        // printstring(a,1600);

        pi(a);
        // printf("\nPi\n");
        // printstring(a,1600);
        chi(a);
        // printf("\nCHi\n");
        // printstring(a,1600);
        iota(a,ir);
        // printf("\nIota\n");
        // printstring(a,1600);
    }
    // // State array to String op
    // state_string(op,a);
}

/* Perform the sponge algorithm
 * m - input string
 * l - non negative integer
 * out - output string
 * out_len - length of output
 */
void sponge(unsigned char *out, unsigned int out_len, unsigned char* m , unsigned int l )
{
    unsigned char *P;
    unsigned long p_len;
    unsigned char *inter;
    unsigned long inter_len;

    // pad(r, len(N))
    inter_len = pad10x1(&inter, 1088, l);

    //  P= N || pad(r, len(N))
    p_len = concatenate(&P,m,l,inter,inter_len);
    unsigned long n = p_len / 1088;
    
    // S = 0 * 200
    unsigned char *S;
    S = (unsigned char*)malloc(200);
    memset(S,0,sizeof(unsigned char));

    // 0 to n-1 S=f(S ^ (Pi || 0c)).
    for (unsigned long i = 0 ; i < n ; i++)
    {
        /* S = S ^ Pi for 136 bytes
         * Remaining 64 bytes of P's are 0
         */
        for ( int j = 0 ; j < 136 ; j++)
        {
            *(S+j) = *(S+j) ^ *(P+j+(i*136));
        }
        // Keccackp -- Change to 24
        keccakp(S, 1600 , 24 , S);
    }

    unsigned char *Z;
    unsigned int Z_len = 0;

    // Z = Z || S 
    Z_len = concatenate(&Z,Z,0,S,1088);

    // While |Z| < 256
    while (Z_len < out_len){
        // S=f(S)
        keccakp(S, 1600 ,24 , S);

        // Z=Z || Truncr(S)
        Z_len = concatenate(&Z,Z,Z_len,S,1088);        
    }

    // Copy 32 bytes of Z to out
    memcpy(out,Z,32);

    // Freeing Memory
    // free(inter);
    // free(P);
    // free(S);
    // free(Z);
}

/* Perform the string to state array
 * z - input state array
 * n - output string
 */
void state_string(unsigned char *n , unsigned char z[5][5][64])
{
    int num = 0;
    int cnt = 0;
    for(int j = 0 ; j < 5 ; j++)
    {
        for(int i = 0 ; i < 5 ; i++)
        {
            for(int k = 0 ; k < 64 ; k+=8)
            {
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
void string_state(unsigned char *n , unsigned char z[5][5][64],unsigned int size)
{
    unsigned int tmp = 0;
    for(int j = 0 ; j < 5 ; j++)
    {
        for(int i = 0 ; i < 5 ; i++)
        {
            for(int k = 0 ; k < 64 ; k+=8)
            {
                tmp = (((64 * ((5 * j) + i))) + (k))/8;
                if(tmp < size)
                {
                    z[i][j][k] = BIT(*(n+tmp),0);
                    z[i][j][k+1] = BIT(*(n+tmp),1);
                    z[i][j][k+2] = BIT(*(n+tmp),2);
                    z[i][j][k+3] = BIT(*(n+tmp),3);
                    z[i][j][k+4] = BIT(*(n+tmp),4);
                    z[i][j][k+5] = BIT(*(n+tmp),5);
                    z[i][j][k+6] = BIT(*(n+tmp),6);
                    z[i][j][k+7] = BIT(*(n+tmp),7);
                }
            }
        }
    }
}

/* Print String of a particular length
 * s - input string
 * len - length of string
 */
void printstring(unsigned char* s,unsigned int len)
{
    printf("Printing String\n");
    for(unsigned int i = 0 ; i < ((len / 8) + (len % 8 ? 1 : 0)); i++)
    {
        printf("%02x ", *(s+i));
    }
}

/* Print 5x5x64 matrix
 * a - input matrix
 */
void print(unsigned char a[5][5][64])
{
    printf("Printing\n");
    int num = 0;
    for(int j = 0 ; j < 5 ; j++)
    {
        for(int i = 0 ; i < 5 ; i++)
        {
            for(int k = 63 ; k > -1 ; k-=8)
            {
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
}

/* Print a 2D matrix
 * a - input matrix
 * l - rows of matrix
 * m - columns of matrix
 */
void print_2d(unsigned char *a, int l, int m)
{
    printf("Printing 2D\n");
    for(int i = 0 ; i < l ; i++)
    {
        for(int j = 0 ; j < m ; j++)
        {
            if(j%8 == 0)
                printf(" ");
            printf("%d", *(a+i+j));
        }
    }
}

/* Print a 5x5x64 matrix byte by byte
 * a - input matrix
 */
void print_in_pairs(unsigned char a[5][5][64])
{
    int num = 0;
    for(int j = 0 ; j < 5 ; j++)
    {
        for(int i = 0 ; i < 5 ; i++)
        {
            for(int k = 0 ; k < 64 ; k+=8)
            {
                num = (a[i][j][k] == 1 ? 1 : 0 )<< (k%8);
                num += (a[i][j][k+1] == 1 ? 1 : 0 )<< ((k+1)%8);
                num += (a[i][j][k+2] == 1 ? 1 : 0 )<< ((k+2)%8);
                num += (a[i][j][k+3] == 1 ? 1 : 0 )<< ((k+3)%8);
                num += (a[i][j][k+4] == 1 ? 1 : 0 )<< ((k+4)%8);
                num += (a[i][j][k+5] == 1 ? 1 : 0 )<< ((k+5)%8);
                num += (a[i][j][k+6] == 1 ? 1 : 0 )<< ((k+6)%8);
                num += (a[i][j][k+7] == 1 ? 1 : 0 )<< ((k+7)%8);
                printf("%02x ", num);
            }
        }
    }
    printf("\n");
}
