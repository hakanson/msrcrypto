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
/// <reference path="testVectors/tv_hmac_sha256.js" />
/// <reference path="testVectors/tv_hmac_sha384.js" />
/// <reference path="testVectors/tv_hmac_sha512.js" />

var hmacKey = null;

var hmacResults = [];

function hmacSignComplete(expectedHex, resultArray, expectedResultCount) {

    return function (e) {

        var macHex = bytesToHexString(getArrayResult(e.target.result));
        resultArray.push({ mac: macHex, expected: expectedHex });

        if (resultArray.length === expectedResultCount) {
            start();
            for (var i = 0; i < resultArray.length; i++) {
                equal(resultArray[i].mac, resultArray[i].expected, "should be " + resultArray[i].expected);
            }
        }
    };

};

function hmacVectorTest(vectors, shaName, sync, process) {

    expect(vectors.length);
    hmacResults = [];

    setAsyncState(!sync);

    for (var i = 0; i < vectors.length; i++) {

        var keyBytes = hexToBytesArray(vectors[i].key);
        var dataBytes = hexToBytesArray(vectors[i].msg);
        var macHex = bytesToHexString(hexToBytesArray(vectors[i].mac));
        var cryptoOp;

        importKeyBytes("hmac", keyBytes, function (key, params) {

            if (process) {
                cryptoOp = subtle.sign({ name: "hmac", hash: { name: shaName } }, key);
            } else {
                cryptoOp = subtle.sign({ name: "hmac", hash: { name: shaName } }, key, params[0]);
            }

            cryptoOp.oncomplete = hmacSignComplete(params[1], hmacResults, vectors.length);

            cryptoOp.onerror = function (e) { ok(false, "Error: " + e.message); };

            if (process) {
                var sections = partitionData(params[0]);
                for (var i = 0; i < sections.length; i++) {
                    cryptoOp.process(sections[i]);
                }
                cryptoOp.finish();
            }

        }, error, [dataBytes, macHex]);
    }
}

module("HMAC");

asyncTest("HMAC KeyImport sync", function () {

    expect(3);

    //clear the global key handle
    hmacKey = null;

    subtle.forceSync = true;

    var keyText = "ufLk4A9NlW5kRN7ODF-6TaiLacMcx4uNncPt3ceiIH0";
    var keyData = keyTextToKeyData("hmac", keyText);

    keyOp = subtle.importKey("jwk", keyData, { name: "hmac", hash: { name: "sha-256" } }, true, []);

    keyOp.oncomplete = function (e) {
        start();
        hmacKey = e.target.result;
        equal(hmacKey.type, "secret", "secret key type");
        equal(hmacKey.algorithm.name, "hmac", hmacKey.algorithm.name + " algorithm name");
        equal(hmacKey.algorithm.hash.name, "sha-256", hmacKey.algorithm.hash.name + " algorithm name");
    };

    keyOp.onerror = function (e) {
        start();
        ok(false, "error: " + (typeof e.message !== "undefined" ? e.message : e.type));
    };

});

asyncTest("HMAC-256 sign async", function () {

    hmacVectorTest(testVectorsHMAC256, "sha-256", false, false);

});

asyncTest("HMAC-384 sign async", function () {

    hmacVectorTest(testVectorsHMAC384, "sha-384", false, false);

});

asyncTest("HMAC-512 sign async", function () {

    hmacVectorTest(testVectorsHMAC512, "sha-512", false, false);

});

asyncTest("HMAC-256 sign async process", function () {

    hmacVectorTest(testVectorsHMAC256, "sha-256", false, true);

});

asyncTest("HMAC-384 sign async process", function () {

    hmacVectorTest(testVectorsHMAC384, "sha-384", false, true);

});

asyncTest("HMAC-512 sign async process", function () {

    hmacVectorTest(testVectorsHMAC512, "sha-512", false, true);

});

asyncTest("HMAC-256 sign sync", function () {

    hmacVectorTest(testVectorsHMAC256, "sha-256", true, false);

});

asyncTest("HMAC-384 sign sync", function () {

    hmacVectorTest(testVectorsHMAC384, "sha-384", true, false);

});

asyncTest("HMAC-512 sign sync", function () {

    hmacVectorTest(testVectorsHMAC512, "sha-512", true, false);

});

asyncTest("HMAC-256 sign sync process", function () {

    hmacVectorTest(testVectorsHMAC256, "sha-256", true, true);

});

asyncTest("HMAC-384 sign sync process", function () {

    hmacVectorTest(testVectorsHMAC384, "sha-384", true, true);

});

asyncTest("HMAC-512 sign sync process", function () {

    hmacVectorTest(testVectorsHMAC512, "sha-512", true, true);

});