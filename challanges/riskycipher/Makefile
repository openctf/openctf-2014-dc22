HEADERS = shared.h client.h server.h md5.h
STATIC = client_static server_static
DYNAMIC = client server
#LIBS = -ltomcrypt
#COMPILE = gcc $(CFLAGS) -O0 -g -pedantic -std=gnu99 -Wall -Wextra -funsigned-char -Wno-pointer-sign
COMPILE = clang $(CFLAGS) -pedantic -Wall -Wextra -funsigned-char -Wno-pointer-sign

.PHONY: dynamic static all clean

.SUFFIXES:
	MAKEFLAGS += -r

dynamic: $(DYNAMIC)

static: $(STATIC)

all: dynamic static test

clean:
	rm -f $(DYNAMIC) $(STATIC) test *.o 2> /dev/null || true

%.o: %.c $(HEADERS)
	$(COMPILE) -c $< -o $@

%_static: %.o shared.o md5.o
	$(COMPILE) -static $^ $(LIBS) -o $@

%: %.o shared.o md5.o
	$(COMPILE) $^ $(LIBS) -o $@
