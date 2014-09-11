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

#ifndef NO_URANDOM
void randbytes(unsigned char *ptr, ssize_t len) {
  int urandom_fd;

  if ((urandom_fd = open("/dev/urandom", O_RDONLY)) < 0) {
    perror("error opening random");
    exit(1);
  }

  if (read(urandom_fd, ptr, len) != len) {
    perror("error reading random");
    exit(1);
  }
}
#else
#include <sys/time.h>
void randbytes(unsigned char *ptr, ssize_t len) {
  unsigned char buf1[16];
  unsigned char buf2[16];
  unsigned char msg[256];

  unsigned char seed[] = "tqeFhiONl31IEGAnLL4pxrJvydudm4rw";
  memcpy(buf1, seed, sizeof(buf1));

  unsigned int out_pos = 0;
  unsigned int msg_pos = 0;

  pid_t pid = getpid();

  gettimeofday((struct timeval *)&msg, NULL);
  msg_pos += sizeof(struct timeval);
  memcpy(msg+msg_pos, &pid, sizeof(pid));

  while (out_pos < len) {
    HMAC_MD5(buf2, buf1, 16, msg, 256);
    if (out_pos + 16 <= len) {
      memcpy(ptr+out_pos, buf2, 16);
    } else {
      memcpy(ptr+out_pos, buf2, len % 16);
    }
    memcpy(buf2, buf1, 16);
    out_pos += 16;
  }
// extern void HMAC_MD5(unsigned char *result, const void *key, unsigned long key_size, const void *data, unsigned long data_size);
}
#endif

int str_encrypt(unsigned char *dst, const unsigned char *src, unsigned char *nonce, const unsigned char *pw) {
  unsigned char rand[IV_RAND_BYTES];

  int i;

  randbytes(rand, IV_RAND_BYTES);

  /* nonce is in hex due to lazyness */
  for (i = 0; i < IV_RAND_BYTES; ++i) {
    sprintf(nonce+(i*2), "%02x", rand[i]);
  }
  nonce[IV_RAND_BYTES*2] = 0;

  strncpy(dst, src, MAX_STRLEN - 1);
  return str_crypt(nonce, pw, dst, MODE_ENCRYPT);
}

int main(int argc, char **argv) {
  unsigned char pw[64];
  unsigned char nonce[IV_RAND_BYTES*2+1];
  unsigned char flagdata[MAX_STRLEN];
  unsigned char encrypted[MAX_STRLEN];
  unsigned char md5_digest[16];
  unsigned char md5_hex[33];

  int i, fd, err;
  ssize_t n;

  if (argc < 3) {
    fprintf(stderr, "usage: server pw flagfile [port]\n");
    return -1;
  }

  if ((fd = open(argv[2], O_RDONLY)) < 0) {
    fprintf(stderr, "failed to open '%s' for reading\n", argv[2]);
    return -1;
  }

  memset(flagdata, 0, sizeof(flagdata));
  if ((n = read(fd, flagdata, sizeof(flagdata) - 1)) < 0) {
    fprintf(stderr, "failed to read '%s'\n", argv[2]);
    return -1;
  }

  if ((err = close(fd)) < 0) {
    fprintf(stderr, "failed to close '%s'\n", argv[2]);
    return -1;
  }

  /* md5 the flagdata for verification */
  MD5(md5_digest, flagdata, strnlen(flagdata, sizeof(flagdata) - 1));
  for (i = 0; i < 16; ++i) {
    sprintf(md5_hex+(i*2), "%02x", md5_digest[i]);
  }
  md5_hex[32] = 0;

  memset(pw, 0, sizeof(pw));
  strncpy(pw, argv[1], sizeof(pw) - 1); 

  if (argc == 4) {
    /* server mode */
    /* mostly lifted from http://www.cs.ucsb.edu/~almeroth/classes/W01.176B/hw2/examples/tcp-server.c */
    int fd_s, fd_c;
    struct sockaddr_in addr_s, addr_c;
    socklen_t len_c;
    pid_t pid_c;

    int reuseaddr=1;

    fd_s = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(fd_s, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));

    bzero(&addr_s, sizeof(addr_s));
    addr_s.sin_family = AF_INET;
    addr_s.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_s.sin_port = htons(atoi(argv[3]));
    bind(fd_s, (struct sockaddr *)&addr_s, sizeof(addr_s));
    listen(fd_s, 256);

    for (;;) {
      len_c = sizeof(addr_c);
      fd_c = accept(fd_s, (struct sockaddr *)&addr_c, &len_c);

      if ((pid_c = fork()) == 0) {
        // fprintf(stderr, "in child\n");
        close(fd_s);
        unsigned char str_addr_c[256];
        inet_ntop(AF_INET, &(addr_c.sin_addr), str_addr_c, sizeof(addr_c));
        fprintf(stderr, "got client: %s:%u\n", str_addr_c, ntohs(addr_c.sin_port));
        str_encrypt(encrypted, flagdata, nonce, pw);
        sendto(fd_c, nonce, 32, 0, (struct sockaddr *)&addr_c, sizeof(addr_c));
        sendto(fd_c, "\n", 1, 0, (struct sockaddr *)&addr_c, sizeof(addr_c));
        sendto(fd_c, md5_hex, 32, 0, (struct sockaddr *)&addr_c, sizeof(addr_c));
        sendto(fd_c, "\n", 1, 0, (struct sockaddr *)&addr_c, sizeof(addr_c));
        sendto(fd_c, encrypted, strnlen(encrypted, MAX_STRLEN - 1), 0, (struct sockaddr *)&addr_c, sizeof(addr_c));
        close(fd_c);
        exit(0);
      } else {
        close(fd_c);
      }
      waitpid(-1, NULL, WNOHANG);
    }
  } else {
    str_encrypt(encrypted, flagdata, nonce, pw);
    printf("%s\n%s\n%s", nonce, md5_hex, encrypted);
    str_crypt(nonce, pw, encrypted, MODE_DECRYPT);
    printf("%s", encrypted);
  }

  return 0;
}
  



/* vim: set ts=2 sw=2 et ai si: */
