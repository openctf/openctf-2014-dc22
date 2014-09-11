This is "straightforward".

1. Extract the RSA modulus and public exponent from BlackNet's public key
2. Factor the modulus (takes 4-6 hours on a fast quad core i7 using factmseive)
3. Use the factors to construct a GPG key
4. Decrypt the message

Each of these steps is a pretty major pain in the arse.

A old, patched version of GnuPG was used to make the keys and messages in this
challange closely match what old versions of PGP would produce.
