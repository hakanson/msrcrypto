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
/// <reference path="test512Vectors/tv_sha384_short.js" />
/// <reference path="test512Vectors/tv_sha384_long.js" />
/// <reference path="test512Vectors/tv_sha384_short.js" />
/// <reference path="test512Vectors/tv_sha384_long.js" />

var hash512Results = [];

function hash512Complete(expectedHex, resultArray, expectedResultCount) {

    return function (e) {

        var hashHex = bytesToHexString(getArrayResult(e.target.result));
        resultArray.push({ hash: hashHex, expected: expectedHex });

        if (resultArray.length === expectedResultCount) {
            start();
            for (var i = 0; i < resultArray.length; i++) {
                equal(resultArray[i].hash, resultArray[i].expected, "should be " + resultArray[i].expected);
            }
        }

    };
};

function test512Vectors(vectors, algorithmName, resultsArray, async, process) {

    expect(vectors.length);
    resultsArray = [];

    setAsyncState(async);

    var cryptoOp;

    for (var i = 0; i < vectors.length; i++) {

        var dataBytes = toSupportedArray(vectors[i].data);
        var expectedHex = bytesToHexString(vectors[i].hash);

        if (process) {
            cryptoOp = subtle.digest({ name: algorithmName});
        } else {
            cryptoOp = subtle.digest({ name: algorithmName}, dataBytes);
        }

        cryptoOp.oncomplete = hash512Complete(expectedHex, resultsArray, vectors.length);

        cryptoOp.onerror = function (e) { ok(false, "Error: " + e.message); };

        if (process) {
            var sections = partitionData(dataBytes);
            for (var j = 0; j < sections.length; j++) {
                cryptoOp.process(sections[j]);
            }
            cryptoOp.finish();
        }
    }
}

// #region SHA-384

module("SHA-384");

asyncTest("SHA-384 vectors short async", function () {

    test512Vectors(testVectorsSha384Short, "sha-384", hash512Results, true, false);

});

asyncTest("SHA-384 vectors long async", function () {

    test512Vectors(testVectorsSha384Long, "sha-384", hash512Results, true, false);

});

asyncTest("SHA-384 vectors short sync", function () {

    test512Vectors(testVectorsSha384Short, "sha-384", hash512Results, false, false);

});

asyncTest("SHA-384 vectors long sync", function () {

    test512Vectors(testVectorsSha384Long, "sha-384", hash512Results, false, false);

});

asyncTest("SHA-384 vectors short async process", function () {

    test512Vectors(testVectorsSha384Short, "sha-384", hash512Results, true, true);

});

asyncTest("SHA-384 vectors long async process", function () {

    test512Vectors(testVectorsSha384Long, "sha-384", hash512Results, true, true);

});

asyncTest("SHA-384 vectors short sync process", function () {

    test512Vectors(testVectorsSha384Short, "sha-384", hash512Results, false, true);

});

asyncTest("SHA-384 vectors long sync process", function () {

    test512Vectors(testVectorsSha384Long, "sha-384", hash512Results, false, true);

});

// #endregion SHA-384

// #region SHA-512

module("SHA-512");

asyncTest("SHA-512 vectors short async", function () {

    test512Vectors(testVectorsSha512Short, "sha-512", hash512Results, true, false);

});

asyncTest("SHA-512 vectors long async", function () {

    test512Vectors(testVectorsSha512Long, "sha-512", hash512Results, true, false);

});

asyncTest("SHA-512 vectors short sync", function () {

    test512Vectors(testVectorsSha512Short, "sha-512", hash512Results, false, false);

});

asyncTest("SHA-512 vectors long sync", function () {

    test512Vectors(testVectorsSha512Long, "sha-512", hash512Results, false, false);

});

asyncTest("SHA-512 vectors short async process", function () {

    test512Vectors(testVectorsSha512Short, "sha-512", hash512Results, true, true);

});

asyncTest("SHA-512 vectors long async process", function () {

    test512Vectors(testVectorsSha512Long, "sha-512", hash512Results, true, true);

});

asyncTest("SHA-512 vectors short sync process", function () {

    test512Vectors(testVectorsSha512Short, "sha-512", hash512Results, false, true);

});

asyncTest("SHA-512 vectors long sync process", function () {

    test512Vectors(testVectorsSha512Long, "sha-512", hash512Results, false, true);

});

// #endregion SHA-512