/* Implement the following API. Do NOT modify the given prototypes. */

/* Compute the SHA-3 hash for a message.
 *
 * d - the output buffer (allocated by the caller)
 * s - size of the output buffer in bits
 * m - the input message
 * l - size of the input message in bits
 */
void sha3(unsigned char *d, unsigned int s, const unsigned char *m,
	  unsigned int l);

/* You can add your own functions below this line.
 * Do NOT modify anything above. */

// String To State and State To String
void string_state(unsigned char *n , unsigned char z[5][5][64],unsigned int size);
void state_string(unsigned char *n , unsigned char z[5][5][64]);
// RND Functions
void theta( uint64_t *a );
void rho( uint64_t *a );
void pi( uint64_t *a );
void chi( uint64_t *a );
void iota( uint64_t *a , unsigned long ir);

void keccakp(unsigned char *s , unsigned int b ,unsigned long nr ,unsigned char* op);
void sponge(unsigned char *out, unsigned int out_len, unsigned char* m , unsigned int l );

// Print Functions
void printstring(unsigned char* s,unsigned int length);
void print(unsigned char a[5][5][64]);
void print_in_pairs(unsigned char a[5][5][64]);
void print_2d(unsigned char *a, int l, int m);
