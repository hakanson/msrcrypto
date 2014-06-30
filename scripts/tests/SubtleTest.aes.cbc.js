//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.14.0.js" />
/// <reference path="testVectors/tv_aes.js" />

var aesCbcTest = {

    aesResults1: [],
    aesResults2: [],
    aesResults3: [],

    waitAes: function (array, length) {
        if (array.length >= length) {
            start();
            for (var i = 0; i < length; i++) {
                equal(bytesToHexString(array[i].result),
                      bytesToHexString(array[i].expected),
                      "tag " + array[i].tag);
            }

        } else {
            setTimeout(
                function () {
                    aesCbcTest.waitAes(array, length);
                }, 100);
        }
    },

    aesComplete: function (resultArray, encryptedBytes, expectedBytes, plainTextBytes, tag) {

        return function (e) {
            var result = toSupportedArray(e.target.result);
            resultArray.push({ result: encryptedBytes, expected: expectedBytes, tag: "enc" });
            resultArray.push({ result: result, expected: plainTextBytes, tag: "dec" });
        };

    },

    aesEncryptionComplete: function (expected) {
        return function (e) {
            start();
            var hashBytes = getArrayResult(e.target.result);
            var result = bytesToHexString(hashBytes);
            var expectedHex = bytesToHexString(expected);
            equal(result, expectedHex, "should be " + expectedHex);
        };
    },

    aesDecryptionComplete: function (expected) {
        return function (e) {
            start();
            var decryptedBytes = getArrayResult(e.target.result);
            var result = String.fromCharCode.apply(null, decryptedBytes);
            var expectedString = String.fromCharCode.apply(null, expected);
            equal(result, expectedString, "should be " + expectedString);
        };
    },

    aesEncrypt: function (keyBytes, dataBytes, ivBytes, expectedBytes, sync, process) {

        var cryptoOp;

        subtle.forceSync = sync;

        importKey("aes-cbc", keyBytes, function (key) {

            if (process) {
                cryptoOp = subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key);

            } else {
                cryptoOp = subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, dataBytes);
            }

            cryptoOp.oncomplete = aesCbcTest.aesEncryptionComplete(expectedBytes);

            cryptoOp.onerror = error;

            if (process) {
                var sections = partitionData(dataBytes);
                for (var i = 0; i < sections.length; i++) {
                    cryptoOp.process(sections[i]);
                }
                cryptoOp.finish();
            }

        }, error);

    },

    aesDecrypt: function (keyBytes, encryptedBytes, ivBytes, expectedBytes, sync, process) {

        var cryptoOp;

        subtle.forceSync = sync;

        importKey("aes-cbc", keyBytes, function (key) {

            if (process) {
                cryptoOp = subtle.decrypt({ name: "AES-CBC", iv: ivBytes }, key);

            } else {
                cryptoOp = subtle.decrypt({ name: "AES-CBC", iv: ivBytes }, key, encryptedBytes);
            }

            cryptoOp.oncomplete = aesCbcTest.aesDecryptionComplete(expectedBytes);

            cryptoOp.onerror = error;

            if (process) {
                var sections = partitionData(encryptedBytes);
                for (var i = 0; i < sections.length; i++) {
                    cryptoOp.process(sections[i]);
                }
                cryptoOp.finish();
            }

        }, error);

    },

    aesRoundTrip: function (resultsArray, keyBytes, dataBytes, ivBytes, expectedBytes, sync, process) {

        var cryptoOpEnc, cryptoOpDec;

        subtle.forceSync = sync;

        var jwkKeyString = utils.toBase64(keyBytes);
        jwkKeyString = jwkKeyString.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        jwkKeyString = keyTextToKeyData("aes", jwkKeyString);

        importKey("aes-cbc", jwkKeyString, function (key) {

            if (process) {
                cryptoOpEnc = subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key);

            } else {
                cryptoOpEnc = subtle.encrypt({ name: "AES-CBC", iv: ivBytes }, key, dataBytes);
            }

            cryptoOpEnc.oncomplete = function (e) {

                var encryptedBytes = getArrayResult(e.target.result);

                if (process) {
                    cryptoOpDec = subtle.decrypt({ name: "AES-CBC", iv: ivBytes }, key);

                } else {
                    cryptoOpDec = subtle.decrypt({ name: "AES-CBC", iv: ivBytes }, key, toSupportedArray(encryptedBytes));
                }

                cryptoOpDec.oncomplete = aesCbcTest.aesComplete(resultsArray, Array.apply([], encryptedBytes), expectedBytes, dataBytes, keyBytes.length.toString());

                cryptoOpDec.onerror = error;

                if (process) {
                    var sections = partitionData(encryptedBytes);
                    for (var j = 0; j < sections.length; j++) {
                        cryptoOpDec.process(sections[j]);
                    }
                    cryptoOpDec.finish();
                }

            }

            cryptoOpEnc.onerror = error;

            if (process) {
                var sections = partitionData(dataBytes);
                for (var i = 0; i < sections.length; i++) {
                    cryptoOpEnc.process(sections[i]);
                }
                cryptoOpEnc.finish();
            }

        }, error);

    },

    aesGenerateKey: function (keySize, sync) {

        expect(4);

        var aesKey = null;

        subtle.forceSync = sync;

        var keyOpGen = subtle.generateKey({ name: "aes-cbc", length: keySize }, true, []);

        keyOpGen.oncomplete = function (e) {
            //start();
            aesKey = e.target.result;
            //equal(aesKey.type, "secret", "secret key type");
            //equal(aesKey.algorithm.name, "aes-cbc", "aes-cbc algorithm name");

            var keyOpExp = subtle.exportKey("jwk", aesKey, true, []);

            keyOpExp.oncomplete = (function (key) {
                return function (e) {
                    // Decode the exported key
                    var keyBytes = getArrayResult(e.target.result);
                    var keyString = String.fromCharCode.apply(null, keyBytes);
                    var keyObject = JSON.parse(keyString);
                    var decodedKeyString = msrCrypto.base64ToString(keyObject.k);
                    keyBytes = [];
                    for (var i = 0; i < decodedKeyString.length; i++) {
                        keyBytes.push(decodedKeyString.charCodeAt(i));
                    }

                    start();

                    equal(key.type, "secret", "secret key type");
                    equal(key.algorithm.name, "aes-cbc", "aes-cbc algorithm name");

                    equal(keyBytes.length, keySize / 8, "expected number of bytes: " + keyBytes.join());
                    equal(keyObject.kty, "oct", "kty=oct");
                }
            })(aesKey);

            keyOpExp.onerror = function (e) {
                ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
            };

        };

        keyOpGen.onerror = function (e) {
            start();
            ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
        };

    },

    aesProcessError: function () {

        var subtle = msCrypto.subtle,
            aesKey,
            iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            plain = new Uint8Array(100);

        // Create some data
        for (var i = 0; i < plain.length; i++) {
            plain[i] = i;
        }

        var keyOpGen = subtle.generateKey({ name: "aes-cbc", length: 256 });

        keyOpGen.oncomplete = function (e) {

            aesKey = e.target.result;

            var cryptoOpEnc = subtle.encrypt({ name: "AES-CBC", iv: iv }, aesKey, plain);

            cryptoOpEnc.oncomplete = function (e1) {

                var cipherBytes = new Uint8Array(e1.target.result);

                cryptoOpDec = subtle.decrypt({ name: "AES-CBC", iv: iv }, aesKey);

                cryptoOpDec.oncomplete = function (e2) {

                    var plainResultBytes = new Uint8Array(e2.target.result);

                    if (!arraysEqual(plain, plainResultBytes)) {
                        alert("Origninal [" + plain.length + "] " + Array.apply(null, plain).join() + '\n\n' +
                           "Decrypted [" + plainResultBytes.length + "] " + Array.apply(null, plainResultBytes).join());
                    }

                    alert("Success");
                }

                cryptoOpDec.onerror = error("Decryption Error");

                // Process the data byte-by-byte
                var dataByte = new Uint8Array(1);
                for (var i = 0; i < cipherBytes.length; i++) {
                    dataByte[0] = cipherBytes[i];
                    cryptoOpDec.process(dataByte);
                }
                cryptoOpDec.finish();
            };

            cryptoOpEnc.onerror = error("Encryption Error");

            // Process the data byte-by-byte
            var dataByte = new Uint8Array(1);
            for (var i = 0; i < plain.length; i++) {
                dataByte[0] = plain[i];
                cryptoOpEnc.process(dataByte);
            }
            cryptoOpEnc.finish();
        };


        keyOpGen.onerror = error("KeyGen Error");

        function arraysEqual(array1, array2) {
            if (array1.length !== array2.length) { return false; }
            for (var i = 0; i < array1.length; i++) {
                if (array1[i] !== array2[i]) { return false; }
            }
            return true;
        }

        function error(label) {
            return function (e) {
                alert(label + " : " + e.message || e.error);
            }
        }

    }

};


module("AES-CBC");


//asyncTest("aesProcessError", function () {

//    aesProcessError();

//});

asyncTest("GenerateKey 128 Sync", function () {

    aesCbcTest.aesGenerateKey(128, true);

});

asyncTest("GenerateKey 192 Sync", function () {

    aesCbcTest.aesGenerateKey(192, true);

});

asyncTest("GenerateKey 256 Sync", function () {

    aesCbcTest.aesGenerateKey(256, true);

});

asyncTest("GenerateKey 128 Async", function () {

    aesCbcTest.aesGenerateKey(128, false);

});

asyncTest("GenerateKey 192 Async", function () {

    aesCbcTest.aesGenerateKey(192, false);

});

asyncTest("GenerateKey 256 Async", function () {

    aesCbcTest.aesGenerateKey(256, false);

});

asyncTest("KeyImport/Export Sync", function () {

    expect(4);

    //clear the global key handle
    aesKey = null;

    subtle.forceSync = true;

    var keyText = "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0";
    var keyData = keyTextToKeyData("aes", keyText);

    var keyOpImp = subtle.importKey("jwk", keyData, { name: "aes-cbc" }, true, []);

    keyOpImp.oncomplete = function (e) {

        aesKey = e.target.result;
        var keyOpExp = subtle.exportKey("jwk", aesKey, { name: "aes-cbc" }, true, []);

        keyOpExp.oncomplete = (
            function (key) {
                return function (e) {
                    start();
                    var keyBytes = getArrayResult(e.target.result);
                    var keyString = String.fromCharCode.apply(null, keyBytes);
                    var keyObject = JSON.parse(keyString);
                    equal(key.type, "secret", "secret key type");
                    equal(key.algorithm.name, "aes-cbc", "aes-cbc algorithm name");
                    equal(keyObject.k, keyText, "k");
                    equal(keyObject.kty, "oct", "kty");
                }
            })(aesKey);

        keyOpExp.onerror = function (e) {
            ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
        };

    };

    keyOpImp.onerror = function (e) {
        start();
        ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
    };

});

asyncTest("KeyImport/Export Async", function () {

    expect(4);

    //clear the global key handle
    var aesKey = null;

    delete subtle.forceSync;

    var keyText = "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0";
    var keyData = keyTextToKeyData("aes", keyText);

    var keyOpImp = subtle.importKey("jwk", keyData, { name: "aes-cbc" }, true, []);

    keyOpImp.oncomplete = function (e) {

        aesKey = e.target.result;

        var keyOpExp = subtle.exportKey("jwk", aesKey, { name: "aes-cbc" }, true, []);

        keyOpExp.oncomplete = (
            function (key) {
                return function (e) {
                    start();
                    var keyBytes = getArrayResult(e.target.result);
                    var keyString = String.fromCharCode.apply(null, keyBytes);
                    var keyObject = JSON.parse(keyString);
                    equal(key.type, "secret", "secret key type");
                    equal(key.algorithm.name, "aes-cbc", "aes-cbc algorithm name");
                    equal(keyObject.k, keyText, "k");
                    equal(keyObject.kty, "oct", "kty");
                }
            })(aesKey);

        keyOpExp.onerror = function (e) {
            ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
        };

    };

    keyOpImp.onerror = function (e) {
        start();
        ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
    };

});

asyncTest("Encrypt Async", function () {

    aesCbcTest.aesEncrypt(
        keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        false,
        false
    );

});

asyncTest("Encrypt Sync", function () {

    aesCbcTest.aesEncrypt(
        keyTextToKeyData("aes", "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        hexToBytesArray("8CD084B7-35ECE917-E6A27079-3273B548-DA95CE63-2EB9AD13-7154F623-44C73D97"),
        true,
        false
    );

});

asyncTest("Encrypt Async Process", function () {

    aesCbcTest.aesEncrypt(
        keyTextToKeyData("aes", "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        hexToBytesArray("8CD084B7-35ECE917-E6A27079-3273B548-DA95CE63-2EB9AD13-7154F623-44C73D97"),
        false,
        true
    );

});

asyncTest("Encrypt Sync Process", function () {

    aesCbcTest.aesEncrypt(
        keyTextToKeyData("aes", "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0"),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        hexToBytesArray("8CD084B7-35ECE917-E6A27079-3273B548-DA95CE63-2EB9AD13-7154F623-44C73D97"),
        true,
        true
    );

});

asyncTest("Decrypt Async", function () {

    aesCbcTest.aesDecrypt(
        keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        false
    );
});

asyncTest("Decrypt Sync", function () {

    aesCbcTest.aesDecrypt(
        keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        false
    );

});

asyncTest("Decrypt Sync Process", function () {

    aesCbcTest.aesDecrypt(
        keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        true,
        true
    );

});

asyncTest("Decrypt Async Process", function () {

    aesCbcTest.aesDecrypt(
        keyTextToKeyData("aes", "_xvC22sbp9LA9ZhQGLQzAzIumXb-jL9iY43VDPChTI8"),
        hexToBytesArray("8D76D59C-AFA12CCA-C16E1932-9E2F900B-EE88AAF1-4B9FFF71-9E3E97B2-33CC25E9"),
        toSupportedArray([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
        textToBytes("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        false,
        true
    );

});

asyncTest("128 vectors ", function () {

    var vectors = testVectorsAESCBC["AES-CBC-128"];

    expect(vectors.length * 2);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = hexToBytesArray(vector.key);
        var ivBytes = hexToBytesArray(vector.iv);
        var ptBytes = hexToBytesArray(vector.pt);
        var ctBytes = hexToBytesArray(vector.ct);

        aesCbcTest.aesRoundTrip(aesCbcTest.aesResults1, keyBytes, ptBytes, ivBytes, ctBytes, false, false);

    }

    aesCbcTest.waitAes(aesCbcTest.aesResults1, vectors.length * 2);

});

asyncTest("192 vectors ", function () {

    var vectors = testVectorsAESCBC["AES-CBC-192"];

    expect(vectors.length * 2);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = hexToBytesArray(vector.key);
        var ivBytes = hexToBytesArray(vector.iv);
        var ptBytes = hexToBytesArray(vector.pt);
        var ctBytes = hexToBytesArray(vector.ct);

        aesCbcTest.aesRoundTrip(aesCbcTest.aesResults2, keyBytes, ptBytes, ivBytes, ctBytes, false, false);

    }

    aesCbcTest.waitAes(aesCbcTest.aesResults2, vectors.length * 2);

});

asyncTest("256 vectors ", function () {

    var vectors = testVectorsAESCBC["AES-CBC-256"];

    expect(vectors.length * 2);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = hexToBytesArray(vector.key);
        var ivBytes = hexToBytesArray(vector.iv);
        var ptBytes = hexToBytesArray(vector.pt);
        var ctBytes = hexToBytesArray(vector.ct);

        aesCbcTest.aesRoundTrip(aesCbcTest.aesResults3, keyBytes, ptBytes, ivBytes, ctBytes, false, false);

    }

    aesCbcTest.waitAes(aesCbcTest.aesResults3, vectors.length * 2);

});