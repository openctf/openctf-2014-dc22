#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"
#include "shared.h"

#define MAX_IV_BYTES 64
#define MAX_PW_BYTES 64

#ifndef MAX
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

int str_crypt(const unsigned char *nonce, const unsigned char *pw, unsigned char *str, int mode) {
  unsigned char key[16];
  unsigned char S[256];
  unsigned char T, K;
  int i, j, c, n, p;

  if (mode != MODE_ENCRYPT && mode != MODE_DECRYPT) {
    fprintf(stderr, "invalid mode %d\n", mode);
    return -1;
  }

  HMAC_MD5(key, pw, strnlen(pw, MAX_PW_BYTES), nonce, strnlen(nonce, MAX_IV_BYTES));

  /* begin ksa */
  for (i = 0; i < 256; ++i) {
    S[i] = i;
  }
  j = 0;
  for (i = 0; i < 256; ++i) {
    j = (j + S[i] + key[i % 16]) & 0xff;
    T = S[i]; S[i] = S[j]; S[j] = T;
  }
  /* end ksa */

  /* begin encrypt/decrypt */
  i = j = 0;
  n = strnlen(str, MAX_STRLEN - 1);
  for (p = 0; p < n; ++p) {
    c = str[p];
    /* don't operate on characters that aren't printable ascii */
    if (c < 32 || c > 126) continue;
    /* begin rc4 prga */
    i = (i + 1) & 0xff;
    j = (j + S[i]) & 0xff;
    T = S[i]; S[i] = S[j]; S[j] = T;
    K = S[(S[i] + S[j]) & 0xff];
    /* end rc4 prga */
    c = (mode == MODE_ENCRYPT ? c + K : c - K);
    /* force into the printable ascii range */
    while (c < 32) c += 95;
    while (c > 126) c -= 95;
    str[p] = c;
  }
  /* end encrypt/decrypt */

  return n;
}

/* vim: set ts=2 sw=2 et ai si: */
