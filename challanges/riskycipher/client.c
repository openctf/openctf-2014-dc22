#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "md5.h"
#include "shared.h"

#define IV_RAND_BYTES 16

int str_decrypt(unsigned char *dst, const unsigned char *src, const unsigned char *pw, const unsigned char *nonce, const unsigned char *md5_chk) {
  unsigned char md5_hex[33];

  int err, n, i;

  unsigned char md5_digest[16];

  /* do the decryption */
  strncpy(dst, src, MAX_STRLEN - 1);
  n = str_crypt(nonce, pw, dst, MODE_DECRYPT);

  /* md5 the flagdata for verification */
  MD5(md5_digest, dst, strnlen(dst, MAX_STRLEN - 1));

  for (i = 0; i < 16; ++i) {
    sprintf(md5_hex+(i*2), "%02x", md5_digest[i]);
  }
  md5_hex[32] = 0;

  if ((err = strncmp(md5_chk, md5_hex, 32)) != 0) {
    return -1;
  } else {
    return n;
  }
}

void doread(int fd, unsigned char *dst, size_t len, ssize_t min) {
  ssize_t n;
  if ((n = recvfrom(fd, dst, len, 0, NULL, NULL)) < min) {
    fprintf(stderr, "socket read failed, only got %zd, expected %zu\n", n, min);
    exit(-1);
  }
}

int main(int argc, char **argv) {
  unsigned char pw[64];

  unsigned char flagdata[MAX_STRLEN];

  unsigned char rbuf[MAX_STRLEN + PREAMBLE_SIZE];

  unsigned char nonce[33];
  unsigned char md5[33];

  int fd, err;

  struct sockaddr_in addr_s;

  if (argc < 4) {
    fprintf(stderr, "usage: client pw ip port\n");
    return -1;
  }

  memset(pw, 0, sizeof(pw));
  strncpy(pw, argv[1], sizeof(pw) - 1);

  fd = socket(AF_INET, SOCK_STREAM, 0);

  bzero(&addr_s, sizeof(addr_s));
  addr_s.sin_family = AF_INET;
  inet_pton(addr_s.sin_family, argv[2], &(addr_s.sin_addr));
  addr_s.sin_port = htons(atoi(argv[3]));

  connect(fd, (struct sockaddr *)&addr_s, sizeof(addr_s));

  doread(fd, nonce, 32, 32);
  nonce[32] = 0;
  //fprintf(stderr, "iv:  %s\n", iv);
  doread(fd, rbuf, 1, 1);

  doread(fd, md5, 32, 32);
  md5[32] = 0;
  //fprintf(stderr, "md5: %s\n", md5);
  doread(fd, rbuf, 1, 1);

  memset(rbuf, 0, sizeof(rbuf));
  doread(fd, rbuf, MAX_STRLEN + PREAMBLE_SIZE - 1, 1);
  //fprintf(stderr, "%s", rbuf);

  if ((err = str_decrypt(flagdata, rbuf, pw, nonce, md5)) >= 0) {
    printf("Correct password! Decrypted payload:\n%s", flagdata);
  } else {
    printf("MD5 mismatch, perhaps you have the wrong password? Encrypted payload:\n%s", rbuf);
  }

  close(fd);

  return 0;
}
  
/* vim: set ts=2 sw=2 et ai si: */
