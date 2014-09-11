A couple teams solved this after much frustration.

The challange is provided as a link to a page on an HTTPS site. Initial
attempts to view the page will fail on any sane browser due to the server
being configured to support only weak ciphers. OpenSSL's `s_client` tool will
work, though. There is nothing of interest on the page itself, nor in the
HTTP headers or the server's certificate. The server, however, is configured
to serve up a chain of certificates. If the intermediate certificate is viewed
in PEM format (e.g. `openssl s_client -showcerts -connect host:port`) the flag
can be seen embedded in it.

Embedding data into a certificate is an exercise left to the reader.
