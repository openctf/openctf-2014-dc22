#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "test.h"
#include "shared.h"

int main(int argc, char **argv) {
  if (argc < 4) return -1;

  unsigned char iv[64];
  unsigned char pw[64];
  unsigned char str[256];

  strncpy(iv,  argv[1], sizeof(iv)  - 1);
  strncpy(pw,  argv[2], sizeof(pw)  - 1);
  strncpy(str, argv[3], sizeof(str) - 1);

  printf("%s\n", str);
  str_crypt(iv, pw, str, MODE_ENCRYPT);
  printf("%s\n", str);
  str_crypt(iv, pw, str, MODE_DECRYPT);
  printf("%s\n", str);
  return 0;
}
/* vim: set ts=2 sw=2 et ai si: */
