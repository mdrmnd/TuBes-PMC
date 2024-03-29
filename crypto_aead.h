#ifndef CRYPTO_AEAD
#define CRYPTO_AEAD

// generating a ciphertext c[0],c[1],...,c[*clen-1]
// from a plaintext m[0],m[1],...,m[mlen-1]
// and associated data ad[0],ad[1],...,ad[adlen-1]
// and secret message number nsec[0],nsec[1],...
// and public message number npub[0],npub[1],...
// and secret key k[0],k[1],...
void string2hexString(char* input, int clen, char* output);
static unsigned char ascii2byte(char *hexstring, unsigned char *bytearray);

int crypto_aead_encrypt(
  unsigned char *c, unsigned long long *clen,
  const unsigned char *m, unsigned long long mlen,
  char *ad, unsigned long long adlen,
  const unsigned char *nsec,
  const unsigned char *npub,
  const unsigned char *k);

// generating a plaintext m[0],m[1],...,m[*mlen-1]
// and secret message number nsec[0],nsec[1],...
// from a ciphertext c[0],c[1],...,c[clen-1]
// and associated data ad[0],ad[1],...,ad[adlen-1]
// and public message number npub[0],npub[1],...
// and secret key k[0],k[1],...
int crypto_aead_decrypt(
  unsigned char *m, unsigned long long *mlen,
  unsigned char *nsec,
  const unsigned char *c, unsigned long long clen,
  char *ad, unsigned long long adlen,
  const unsigned char *npub,
  const unsigned char *k);

#endif