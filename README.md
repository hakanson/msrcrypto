msrcrypto
=========

Please review the MICROSOFT RESEARCH LICENSE TERMS before using.  This version has modified files under the terms of personal experimentation.  Changes can be tracked via the Github [issues][1] or the [commit][2] history.

[1]: https://github.com/hakanson/msrcrypto/issues
[2]: https://github.com/hakanson/msrcrypto/commits/master
=========
**Microsoft Research JavaScript Cryptography Library**

The Microsoft Research JavaScript Cryptography Library has been developed for use with cloud services in an HTML5 compliant and forward-looking manner. The algorithms are exposed via the W3C WebCrypto interface, and are tested against the Internet Explorer 11 implementation of that interface. The library currently supports RSA encrypt/decrypt (PKCS#1 v1.5, OAEP, and PSS), AES-CBC and GCM encrypt/decrypt, SHA-256/384/512, HMAC with supported hash functions, PRNG (AES-CTR based) as specified by NIST, ECDH, ECDSA, and KDF (Concat mode). The W3C WebCrypto interface does not yet implement promises. The library is tested on IE8,9,10,11, and latest Firefox, Chrome, Opera, and Safari browsers. This library includes big number integer arithmetic to support the aforementioned cryptographic algorithms. It supports unsigned big integer arithmetic with addition, subtraction, multiplication, division, reduction, inversion, GCD, extended Euclidean algorithm (EEA), Montgomery multiplication, and modular exponentiation. It provides useful utility functions, such as endianness management and conversion routines. The big integer library is likely to change in future releases. There are also unit tests and some sample code. This library is under active development. Future updates to this library may change the programming interfaces.
