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
/// <reference path="testVectors/tv_aes_gcm.js" />

var aesGcmTest = {

    aesResults1: [],
    aesResults2: [],
    aesResults3: [],

    splitResult: function (cipherBytes, tagLengthInBytes) {

        var cipherBytesArray = getArrayResult(cipherBytes);

        return {
            tagBytes: cipherBytesArray.slice(-(tagLengthInBytes)),
            cipherBytes: cipherBytesArray.slice(0, cipherBytesArray.length - tagLengthInBytes)
        };
    },

    waitAes: function (array, length) {
        if (array.length >= length) {
            start();
            for (var i = 0; i < length; i++) {
                equal(bytesToHexString(array[i].result),
                      bytesToHexString(array[i].expected),
                      array[i].tag);
            }

        } else {
            setTimeout(
                function () {
                    aesGcmTest.waitAes(array, length);
                }, 100);
        }
    },

    aesComplete: function (resultStorageArray, encryptionResult, expected) {

        return function (e) {
            var decryptedBytes = getArrayResult(e.target.result);

            resultStorageArray.push({
                result: decryptedBytes,
                expected: expected.plainBytes,
                tag: "Decrypted: " + bytesToHexString(decryptedBytes) + " | " +
                     "Plain: " + bytesToHexString(expected.plainBytes)
            });

            resultStorageArray.push({
                result: encryptionResult.cipherBytes,
                expected: expected.cipherBytes,
                tag: "Encrypted: " + bytesToHexString(expected.cipherBytes) + " | " +
                     "Expected: " + bytesToHexString(encryptionResult.cipherBytes)
            });

            resultStorageArray.push({
                result: encryptionResult.tagBytes,
                expected: expected.tagBytes,
                tag: "Tag: " + bytesToHexString(encryptionResult.tagBytes) + " | " +
                     "Expected: " + bytesToHexString(expected.tagBytes)
            });
        };

    },

    aesEncryptionComplete: function (expectedCipher, expectedTag, algorithm) {
        return function (e) {
            start();

            var result = getArrayResult(e.target.result);

            var tagLength = (algorithm.tagLength || 128) / 8;

            var cipherBytes = result.slice(0, result.length - tagLength);

            var tagBytes = result.slice(-tagLength);

            var cipherHex = bytesToHexString(cipherBytes);

            var expectedCipherHex = bytesToHexString(expectedCipher);

            var tagHex = bytesToHexString(tagBytes);

            var expectedTagHex = bytesToHexString(expectedTag);

            equal(cipherHex, expectedCipherHex, "should be " + expectedCipherHex);
            equal(tagHex, expectedTagHex, "should be " + expectedTagHex);
        };
    },

    aesDecryptionComplete: function (expectedPlain) {
        return function (e) {
            start();

            var cipherBytes = getArrayResult(e.target.result);

            var plainHex = bytesToHexString(cipherBytes);

            var expectedPlainHex = bytesToHexString(expectedPlain);

            equal(plainHex, expectedPlainHex, "should be " + expectedPlainHex);
        };
    },

    aesEncrypt: function (keyBytes, dataBytes, ivBytes, additionalDataBytes, tagLength, expectedBytes, expectedTag, sync, process) {

        var cryptoOp;

        subtle.forceSync = sync;

        importKey("aes-gcm", keyBytes, function (key) {

            var algorithm = {
                name: "AES-GCM",
                iv: ivBytes,
                additionalData: additionalDataBytes,
                tagLength: tagLength
            }

            if (process) {
                cryptoOp = subtle.encrypt(algorithm, key);

            } else {
                cryptoOp = subtle.encrypt(algorithm, key, dataBytes);
            }

            cryptoOp.oncomplete = aesGcmTest.aesEncryptionComplete(expectedBytes, expectedTag, algorithm);

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

    aesDecrypt: function (keyBytes, encryptedBytes, tagBytes, ivBytes, additionalDataBytes, tagLength, expectedBytes, sync, process) {

        var cryptoOp;

        subtle.forceSync = sync;

        importKey("aes-gcm", keyBytes, function (key) {

            var algorithm = {
                name: "AES-GCM",
                iv: ivBytes,
                additionalData: additionalDataBytes,
                tagLength: tagLength
            }

            encryptedBytes = toSupportedArray(encryptedBytes.concat(tagBytes));

            if (process) {
                cryptoOp = subtle.decrypt(algorithm, key);

            } else {
                cryptoOp = subtle.decrypt(algorithm, key, encryptedBytes);
            }

            cryptoOp.oncomplete = aesGcmTest.aesDecryptionComplete(expectedBytes);

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

    aesRoundTrip: function (resultStorageArray, keyBytes, plainBytes, addBytes, ivBytes, expected, sync, process) {

        var cryptoOpEnc, cryptoOpDec;

        subtle.forceSync = sync;

        var jwkKeyString = utils.toBase64(keyBytes);
        jwkKeyString = jwkKeyString.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
        jwkKeyString = keyTextToKeyData("aes", jwkKeyString);

        importKey("aes-gcm", jwkKeyString, function (key) {

            var algorithm = {
                name: "AES-GCM",
                iv: ivBytes
            }

            // If there is not additional data, add the optional empty array to the alg object half the time
            if (addBytes.length > 0 || flip(50)) {
                algorithm.additionalData = addBytes;
            }

            algorithm.tagLength = expected.tagBytes.length * 8;

            if (process) {
                cryptoOpEnc = subtle.encrypt(algorithm, key);

            } else {
                cryptoOpEnc = subtle.encrypt(algorithm, key, plainBytes);
            }

            cryptoOpEnc.oncomplete = function (e) {

                var cipherPlusTagResult = toSupportedArray(e.target.result);

                var encryptionResult = aesGcmTest.splitResult(e.target.result, expected.tagBytes.length);

                if (process) {
                    cryptoOpDec = subtle.decrypt(algorithm, key);

                } else {
                    cryptoOpDec = subtle.decrypt(algorithm, key, cipherPlusTagResult);
                }

                cryptoOpDec.oncomplete = aesGcmTest.aesComplete(resultStorageArray, encryptionResult, expected);

                cryptoOpDec.onerror = error;

                if (process) {
                    var sections = partitionData(cipherPlusTagResult);
                    for (var j = 0; j < sections.length; j++) {
                        cryptoOpDec.process(sections[j]);
                    }
                    cryptoOpDec.finish();
                }

            }

            cryptoOpEnc.onerror = error;

            if (process) {
                var sections = partitionData(plainBytes);
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

        var keyOpGen = subtle.generateKey({ name: "AES-GCM", length: keySize }, true, []);

        keyOpGen.oncomplete = function (e) {
            //start();
            aesKey = e.target.result;
            //equal(aesKey.type, "secret", "secret key type");
            //equal(aesKey.algorithm.name, "AES-GCM", "AES-GCM algorithm name");

            var keyOpExp = subtle.exportKey("jwk", aesKey, { name: "AES-GCM" }, true, []);

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
                    equal(key.algorithm.name, "AES-GCM", "AES-GCM algorithm name");

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

        var keyOpGen = subtle.generateKey({ name: "AES-GCM", length: 256 });

        keyOpGen.oncomplete = function (e) {

            aesKey = e.target.result;

            var cryptoOpEnc = subtle.encrypt({ name: "AES-GCM", iv: iv }, aesKey, plain);

            cryptoOpEnc.oncomplete = function (e1) {

                var cipherBytes = new Uint8Array(e1.target.result);

                cryptoOpDec = subtle.decrypt({ name: "AES-GCM", iv: iv }, aesKey);

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
}

module("AES-GCM");


for (var i = 0; i < 2; i++) {

    for (var j = 0; j < 2; j++) {

        var process = (j === 1);
        var sync = (i === 1);

        var syncLable = sync ? " Sync" : " Async";
        var processLable = process ? " Process" : " ";

        asyncTest("Encrypt" + syncLable + processLable, function () {

            aesGcmTest.aesEncrypt(

                // Key
                keyTextToKeyData("aes", hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // PlainText
                toSupportedArray(hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")),

                // IV
                toSupportedArray(hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                toSupportedArray([]),

                // TagLength
                128,

                // Expected Cipher
                hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985 "),

                // Expected Tag
                hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4"),

                // Sync
                sync,

                // Process
                process
            );

        });

        asyncTest("Decrypt" + syncLable + processLable, function () {

            aesGcmTest.aesDecrypt(

                // Key
                keyTextToKeyData("aes", hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // Cipher
                hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"),

                // Tag
                hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4"),

                // IV
                toSupportedArray(hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                toSupportedArray([]),

                // TagLength
                128,

                // Expected Plain
                hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255 "),

                // Sync
                sync,

                // Process
                process

            );
        });

        asyncTest("Encrypt " + syncLable + processLable, function () {

            aesGcmTest.aesEncrypt(

                // Key
                keyTextToKeyData("aes", hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // PlainText
                toSupportedArray(hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")),

                // IV
                toSupportedArray(hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                toSupportedArray([]),

                // TagLength
                128,

                // Expected Cipher
                hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985 "),

                // Expected Tag
                hexToBytes("4d5c2af327cd64a62cf35abd2ba6fab4"),

                // Sync
                sync,

                // Process
                process
            );

        });

        asyncTest("Decrypt " + syncLable + processLable, function () {

            aesGcmTest.aesDecrypt(

                // Key
                keyTextToKeyData("aes", hexStringToBase64Url("feffe9928665731c6d6a8f9467308308")),

                // Cipher
                hexToBytes("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"),

                // Tag
                hexToBytes("4d5c2af327cd64a62cf35abd2b"),

                // IV
                toSupportedArray(hexToBytes("cafebabefacedbaddecaf888")),

                // AdditionalData
                toSupportedArray([]),

                // TagLength
                104,

                // Expected Plain
                hexToBytes("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255 "),

                // Sync
                sync,

                // Process
                process

            );
        });

    }
}


asyncTest("128 vectors ", function () {

    var vectors = testVectorsAESGCM["AES-128-GCM"];

    expect(vectors.length * 3);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = hexToBytesArray(vector.key);
        var ivBytes = hexToBytesArray(vector.iv);
        var ptBytes = hexToBytesArray(vector.pt);
        var addBytes = hexToBytesArray(vector.add);

        var expected = {
            tagBytes: hexToBytesArray(vector.tag),
            cipherBytes: hexToBytesArray(vector.ct),
            plainBytes: ptBytes
        }

        aesGcmTest.aesRoundTrip(aesGcmTest.aesResults1, keyBytes, ptBytes, addBytes, ivBytes, expected, false, false);

    }

    aesGcmTest.waitAes(aesGcmTest.aesResults1, vectors.length * 3);

});

asyncTest("192 vectors ", function () {

    var vectors = testVectorsAESGCM["AES-192-GCM"];

    expect(vectors.length * 3);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = hexToBytesArray(vector.key);
        var ivBytes = hexToBytesArray(vector.iv);
        var ptBytes = hexToBytesArray(vector.pt);
        var addBytes = hexToBytesArray(vector.add);

        var expected = {
            tagBytes: hexToBytesArray(vector.tag),
            cipherBytes: hexToBytesArray(vector.ct),
            plainBytes: ptBytes
        }

        aesGcmTest.aesRoundTrip(aesGcmTest.aesResults2, keyBytes, ptBytes, addBytes, ivBytes, expected, false, false);

    }

    aesGcmTest.waitAes(aesGcmTest.aesResults2, vectors.length * 3);

});

asyncTest("256 vectors ", function () {

    var vectors = testVectorsAESGCM["AES-256-GCM"];

    expect(vectors.length * 3);

    for (var i = 0; i < vectors.length; i++) {

        var vector = vectors[i];

        var keyBytes = hexToBytesArray(vector.key);
        var ivBytes = hexToBytesArray(vector.iv);
        var ptBytes = hexToBytesArray(vector.pt);
        var addBytes = hexToBytesArray(vector.add);

        var expected = {
            tagBytes: hexToBytesArray(vector.tag),
            cipherBytes: hexToBytesArray(vector.ct),
            plainBytes: ptBytes
        }

        aesGcmTest.aesRoundTrip(aesGcmTest.aesResults3, keyBytes, ptBytes, addBytes, ivBytes, expected, false, false);

    }

    aesGcmTest.waitAes(aesGcmTest.aesResults3, vectors.length * 3);

});