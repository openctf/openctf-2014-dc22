Nobody managed to solve this one during OpenCTF. We did have a reference
solution written by the creator of this challange as well as a test-solve
by a second person. We verified it was possible over dial-up.

When one connects to the given ip/port, the server replies with three lines -
two strings of thirty-two hex digits and some "random looking grabage". The
first line is a nonce which is combined with the password via HMAC-MD5 to
derive a key. The second line is the MD5 of the plaintext. The third line is
the ciphertext.

The encryption algorithm used is based on RC4 with some modifications that
make it [format preserving](https://en.wikipedia.org/wiki/Format-preserving_encryption)
but in doing so introduce a slight statistical bias. Each time a connection
is made to the server, the plaintext is encrypted under a new key and sent
back to the client. The plaintext can be recovered reliably with about 10k
ciphertexts.

We expected teams to reverse the client binary to figure out what it does, then
collect data and implement the plaintext recovery. The flavor text implies that
trying to brute force the password would be futile. The critical function is
`str_encrypt`. RC4 was chosen as the cipher because it is very simple and
common, and the key scheduling algorithm is fairly clear even in a dumb
disassembly. The MD5 of the plaintext is included to allow solutions to be
verified without punding on the scoring server.

Our reference solution is provided here. The ciphertexts can be collected with
netcat wrapped in a for loop.

```python
#!/usr/bin/env python

import sys

data = {}

# read collected data, keeping a count of how many times
# each character shows up in each position as we go
with open(sys.argv[1]) as f:
    for line in f:
        line = line.rstrip('\n')
        for i in xrange(len(line)):
            c = line[i]
            if i not in data:
                data[i] = {}
            if c not in data[i]:
                data[i][c] = 0
            data[i][c] += 1

chars = map(chr, range(32, 127))
n_chars = len(chars)

solution = ''

"""
If we plotted a histogram of the character frequenies for the encryption of
the letter 'f' in a simmilar algorithm that only handles lower case letters
it would look something like this:

     # #  #  #    # 
     ##############
 #   ###############  ## #
##########################
##########################
abcdefghijklmnopqrstuvwxyx
     *

The plaintext letter can be identified by finding the 'rising edge' of the
section of the histrogram containg the slightly more common values.
"""

for i in data:
    best_n = 0
    best_c = ' '
    for j in xrange(n_chars):
        n = 0
        for k in xrange(256 % n_chars):
            c = chars[(j+k) % n_chars]
            n += data[i][c]
        if n > best_n:
            best_n = n
            best_c = chars[j]

    solution += best_c

print solution
```
