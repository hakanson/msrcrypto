/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.14.0.js" />
/// <reference path="testVectors/tv_aes.js" />

module("ECDH");

var q1 = {
    kty: "ec",
    extractable: true,
    crv: "P-256",
    x: msrCrypto.stringToBase64([0x1B, 0x16, 0x31, 0xC5, 0xDC, 0x76, 0xD3, 0x78, 0xA9, 0x14, 0xC9, 0x67, 0x29, 0xD0, 0xA5, 0x94, 0xD5, 0x4B, 0x4F, 0x58, 0x84, 0x5B, 0x1D, 0x4A, 0x4B, 0x6B, 0xE7, 0x39, 0xCA, 0x4A, 0x18, 0xEA]),
    y: msrCrypto.stringToBase64([0x4F, 0x85, 0xE4, 0xC9, 0x26, 0xEE, 0x53, 0x23, 0x90, 0xAA, 0x7C, 0xD4, 0x14, 0x94, 0x35, 0x37, 0x25, 0xE6, 0xE8, 0x04, 0x71, 0x4A, 0xA6, 0x9D, 0x67, 0x07, 0x2F, 0x65, 0xDB, 0x62, 0x5E, 0x07]),
    d: msrCrypto.stringToBase64([0x8F, 0xED, 0x78, 0x43, 0x1D, 0x82, 0x55, 0x8D, 0x90, 0x06, 0xC3, 0xDE, 0xB0, 0x6A, 0xB5, 0x8D, 0x9D, 0xCC, 0xC9, 0x71, 0x06, 0x87, 0x5C, 0x67, 0x25, 0xD5, 0xF1, 0x66, 0x25, 0x5B, 0xA9, 0x0A])
}

var q2 = {
    kty: "ec",
    extractable: true,
    crv: "P-256",
    x: msrCrypto.stringToBase64([0x2A, 0xF5, 0x02, 0xF3, 0xBE, 0x89, 0x52, 0xF2, 0xC9, 0xB5, 0xA8, 0xD4, 0x16, 0x0D, 0x09, 0xE9, 0x71, 0x65, 0xBE, 0x50, 0xBC, 0x42, 0xAE, 0x4A, 0x5E, 0x8D, 0x3B, 0x4B, 0xA8, 0x3A, 0xEB, 0x15]),
    y: msrCrypto.stringToBase64([0xEB, 0x0F, 0xAF, 0x4C, 0xA9, 0x86, 0xC4, 0xD3, 0x86, 0x81, 0xA0, 0xF9, 0x87, 0x2D, 0x79, 0xD5, 0x67, 0x95, 0xBD, 0x4B, 0xFF, 0x6E, 0x6D, 0xE3, 0xC0, 0xF5, 0x01, 0x5E, 0xCE, 0x5E, 0xFD, 0x85]),
    d: msrCrypto.stringToBase64([0x81, 0x42, 0x64, 0x14, 0x5F, 0x2F, 0x56, 0xF2, 0xE9, 0x6A, 0x8E, 0x33, 0x7A, 0x12, 0x84, 0x99, 0x3F, 0xAF, 0x43, 0x2A, 0x5A, 0xBC, 0xE5, 0x9E, 0x86, 0x7B, 0x72, 0x91, 0xD5, 0x07, 0xA3, 0xAF])
}

function ecdhError(message) {
    return function (e) {
        start();
        ok(false, message);
    }
}

function getKeyFromBytes(privateKeyBytes, callback, callbackParam) {

    var privateKey = {
        "kty": "EC",
        "extractable": true,
        "d": msrCrypto.stringToBase64(privateKeyBytes),
        "crv": "P-256"
    }

    var keyBytes = textToBytes(JSON.stringify(privateKey));

    var keyOpImport = subtle.importKey("jwk", keyBytes, { name: "ecdh", namedCurve: "P-256" }, true, []);

    keyOpImport.oncomplete = function (e) {

        callback(e.target.result, callbackParam);
    }
}

var keyQ1d = [0x8F, 0xED, 0x78, 0x43, 0x1D, 0x82, 0x55, 0x8D, 0x90, 0x06, 0xC3, 0xDE, 0xB0, 0x6A, 0xB5, 0x8D, 0x9D, 0xCC, 0xC9, 0x71, 0x06, 0x87, 0x5C, 0x67, 0x25, 0xD5, 0xF1, 0x66, 0x25, 0x5B, 0xA9, 0x0A];
var keyQ2d = [0x81, 0x42, 0x64, 0x14, 0x5F, 0x2F, 0x56, 0xF2, 0xE9, 0x6A, 0x8E, 0x33, 0x7A, 0x12, 0x84, 0x99, 0x3F, 0xAF, 0x43, 0x2A, 0x5A, 0xBC, 0xE5, 0x9E, 0x86, 0x7B, 0x72, 0x91, 0xD5, 0x07, 0xA3, 0xAF];

asyncTest("ECDH/KDF Test", function () {

    var algorithm = { name: "ecdh", namedCurve: "P-256" };

    var key1Bytes = textToBytes(JSON.stringify(q1));
    var key2Bytes = textToBytes(JSON.stringify(q2));

    var key1Handle, key2Handle;

    var keyOpImport1 = subtle.importKey("jwk", key1Bytes, algorithm, true, []);

    keyOpImport1.oncomplete = function (e1) {

        key1Handle = e1.target.result;

        var keyOpImport2 = subtle.importKey("jwk", key2Bytes, algorithm, true, []);

        keyOpImport2.oncomplete = function (e2) {

            key2Handle = e2.target.result;

            var cryptoOp = msrCrypto.subtle.deriveBits(
                    {
                        name: "ecdh",
                        namedCurve: "P-256",
                        publicKey: key1Handle
                    },
                    key2Handle);

            cryptoOp.oncomplete = function (e) {

                var secret = getArrayResult(e.target.result);

                var aesKey = {
                    "kty": "oct",
                    "extractable": true,
                    "k": msrCrypto.stringToBase64(secret),
                }

                var keyBytes3 = textToBytes(JSON.stringify(aesKey));

                var keyOpImport3 = subtle.importKey("jwk", keyBytes3, { name: "aes-cbc" }, true, []);

                keyOpImport3.oncomplete = function (e3) {

                    var aesKey = e3.target.result;

                    var dbAlg = {
                        name: "CONCAT",
                        hash: { name: "sha-256" },
                        algorithmId: [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0],
                        partyUInfo: [0x41, 0x4C, 0x49, 0x43, 0x45, 0x31, 0x32, 0x33],
                        partyVInfo: [0x42, 0x4F, 0x42, 0x42, 0x59, 0x34, 0x35, 0x36]
                    };

                    var keyOpDeriveBits = msrCrypto.subtle.deriveBits(dbAlg, aesKey, 64);

                    keyOpDeriveBits.oncomplete = function (e4) {

                        var derivedBytes = getArrayResult(e4.target.result);

                        var expected =
                            [0xC5, 0xBA, 0xF9, 0x2F, 0x8E, 0xBB, 0xE3, 0x30, 0x4A, 0x6C, 0xF6, 0x82, 0x76, 0x4B, 0xDC, 0x7F, 0x55, 0x94, 0x7A, 0x16, 0xDC, 0xDB, 0x57, 0x2A, 0x0A, 0x0D, 0x20, 0xA0, 0x5A, 0x47, 0xBB, 0xC4, 0x37, 0xFC, 0x7C, 0x97, 0xC2, 0x70, 0x00, 0x09, 0xC8, 0x83, 0x7D, 0x75, 0x75, 0x4E, 0x57, 0x96, 0xCD, 0xFF, 0x53, 0x7F, 0x62, 0xD8, 0x7E, 0x7F, 0x5D, 0x2B, 0x6D, 0xF6, 0x83, 0x73, 0x67, 0xA8];

                        start();

                        equal(derivedBytes.join(), expected.join(), "Expected Secret");

                    }

                }


            }


        };

    }


});

//asyncTest("GenerateKey", function () {

//    var algorithm = { name: "ecdh", namedCurve: "P-256" };

//    var keyOpGen = msrCrypto.subtle.generateKey(algorithm, true, []);

//    keyOpGen.oncomplete = function (e) {

//        var ecKeyPair = e.target.result;

//        //getKeyData(ecKeyPair.privateKey, function (privateKeyObject, publicKeyObject) {

//        //    var keyText = JSON.stringify(privateKeyObject);

//        //}, null);

//        getKeyFromBytes(keyQ1d, function (key1, parameter) {

//            getKeyFromBytes(keyQ2d, function (key2, key1) {

//                var cryptoOp = msrCrypto.subtle.deriveBits(
//                        {
//                            name: "ecdh",
//                            namedCurve: "P-256",
//                            publicKey: key1
//                        },
//                        key2);

//                cryptoOp.oncomplete = function (e) {
//                    var secret = getArrayResult(e.target.result);
//                }

//                cryptoOp.onerror = ecdhError("deriveBits error");

//            }, key1);

//        }, null);




//        // var keyOpExport = msrCrypto.subtle.exportKey("jwk", ecKeyPair.publicKey);

//        // getKeyData(ecKeyPair.publicKey, function (publicKeyObject) {

//        //    getKeyData(ecKeyPair.privateKey, function (privateKeyObject, publicKeyObject) {


//        //        var cryptoOp = msrCrypto.subtle.deriveBits({ name: "ecdh", namedCurve: "P-256", publicKey:  }, ecKeyPair.publicKey);



//        //        start();

//        //        ok(true);

//        //    }, publicKeyObject);

//        //}, null);

//    }

//    keyOpGen.onerror = ecdhError("Keygen error");

//});



