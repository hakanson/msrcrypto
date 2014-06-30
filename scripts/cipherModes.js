var msrcryptoCipherModes = (function () {
    var utils = (function () {

        return {
            xorVectors: function (a, b) {
                /// <summary>XOR two vectors.</summary>
                /// <param name="a" type="array">Input vector.</param>
                /// <param name="b" type="array">Input vector.</param>
                /// <returns type="array">XORed array.</returns>
                var i, res = [], length = Math.min(a.length, b.length);
                for (i = 0 ; i < length ; ++i) {
                    res.push(a[i] ^ b[i]);
                }
                return res;
            },
            getZeroVector: function (length) {
                var res = [];
                var i;
                for (i = 0; i < length; ++i) {
                    res[i] = 0;
                }
                return res;
            }
        };
    })();

    var chaining = (function () {

        return {
            CBC: {
                encrypt: function (iv, plain, key, cipherBlock) {
                    /// <summary>Cipher Block Chaining</summary>
                    /// <param name="iv" type="byte[]">initialization vector</param>
                    /// <param name="plain" type="byte[][]">the plain text, formatted as bi-dimensional byte array</param>
                    /// <param name="key" type="byte[]">the key, as byteArray</param>
                    /// <param name="cipherBlock" type="function">the method to encrypt each block of plaintext</param>
                    /// <returns type="byte[][]"></returns>
                    var newIv = iv.slice(0, iv.length), res = [], i;
                    for (i = 0 ; i < plain.length; ++i) {
                        var toEncrypt = utils.xorVectors(newIv, plain[i]);
                        res.push(cipherBlock(toEncrypt, key));
                        newIv = res[i];
                    }

                    return res;
                },

                decrypt: function (iv, encrypted, key, cipherBlock) {
                    /// <summary>Cipher Block Chaining</summary>
                    /// <param name="iv" type="byte[]">initialization vector</param>
                    /// <param name="encrypted" type="byte[][]">the plain text, formatted as bi-dimensional byte array</param>
                    /// <param name="key" type="byte[]">the key, as byteArray</param>
                    /// <param name="cipherBlock" type="function">the method to encrypt each block of plaintext</param>
                    /// <returns type="byte[][]"></returns>
                    var newIv = iv.slice(0, iv.length), res = [], i;
                    for (i = 0 ; i < encrypted.length; ++i) {
                        var toDecrypt = encrypted[i].slice(0, encrypted[i].length);
                        var decrypted = cipherBlock(toDecrypt, key);
                        res.push(utils.xorVectors(newIv, decrypted));
                        newIv = encrypted[i];
                    }

                    return res;
                }
            }
        };
    })();

    var chaining1 = (function () {

        return {
            CBC: {
                encrypt: function (iv, plain, cipherECB) {
                    /// <summary>Cipher Block Chaining</summary>
                    /// <param name="iv" type="byte[]">initialization vector</param>
                    /// <param name="plain" type="byte[][]">the plain text, formatted as bi-dimensional byte array</param>
                    /// <param name="key" type="byte[]">the key, as byteArray</param>
                    /// <param name="cipherEB" type="function">the method to encrypt each block of plaintext in ECB mode</param>
                    /// <returns type="byte[][]"></returns>
                    var newIv = iv.slice(0, iv.length), res = [], i;
                    for (i = 0 ; i < plain.length; ++i) {
                        var toEncrypt = utils.xorVectors(newIv, plain[i]);
                        res.push(cipherECB(toEncrypt));
                        newIv = res[i];
                    }

                    return res;
                },

                decrypt: function (iv, encrypted, cipherECB) {
                    /// <summary>Cipher Block Chaining</summary>
                    /// <param name="iv" type="byte[]">initialization vector</param>
                    /// <param name="encrypted" type="byte[][]">the plain text, formatted as bi-dimensional byte array</param>
                    /// <param name="key" type="byte[]">the key, as byteArray</param>
                    /// <param name="cipherECB" type="function">the method to decrypt each block of plaintext in ECB mode</param>
                    /// <returns type="byte[][]"></returns>
                    var newIv = iv.slice(0, iv.length), res = [], i;
                    for (i = 0 ; i < encrypted.length; ++i) {
                        var toDecrypt = encrypted[i].slice(0, encrypted[i].length);
                        var decrypted = cipherECB(toDecrypt);
                        res.push(utils.xorVectors(newIv, decrypted));
                        newIv = encrypted[i];
                    }

                    return res;
                }
            }
        };
    })();


    var padding = (function () {

        return {
            PKCSV7: function (message, blockSize) {
                /// <summary>apply PKCS7 padding to message, which is updated</summary>
                /// <param name="message" type="byte[][]"></param>
                /// <param name="blockSize" type="int"></param>
                /// <returns type="void"></returns>
                var lastIndex = message.length - 1 >= 0 ? message.length - 1 : 0;
                var lastBlock = message[lastIndex];
                var length = lastBlock.length;
                var createNewBlock = (length === blockSize);
                if (createNewBlock) {
                    var newBlock = [], i;
                    for (i = 0 ; i < blockSize; ++i) {
                        newBlock.push(blockSize);
                    }
                    message.push(newBlock);
                } else {
                    var byteToAdd = (blockSize - length) & 0xff;
                    while (lastBlock.length !== blockSize) {
                        lastBlock.push(byteToAdd);
                    }
                }
            }
        };
    })();

    return {
        utils: utils,
        chaining: chaining,
        padding: padding
    };
})();
