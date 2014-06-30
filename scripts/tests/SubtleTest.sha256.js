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
/// <reference path="testVectors/tv_sha224_short.js" />
/// <reference path="testVectors/tv_sha224_long.js" />
/// <reference path="testVectors/tv_sha256_short.js" />
/// <reference path="testVectors/tv_sha256_long.js" />

var hash256Results = [];

function hash256Complete(expectedHex, resultArray, expectedResultCount) {

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

function aesVectorTest(vectorArray, resultsArray, shaAlgName, sync, process) {

    expect(vectorArray.length);
    resultsArray = [];

    setAsyncState(!sync);

    for (var i = 0; i < vectorArray.length; i++) {

        var dataBytes = toSupportedArray(vectorArray[i].data);
        var expectedHex = bytesToHexString(vectorArray[i].hash);
        var cryptoOp;

        if (process) {
            cryptoOp = subtle.digest({ name: shaAlgName });
        } else {
            cryptoOp = subtle.digest({ name: shaAlgName }, dataBytes);
        }

        cryptoOp.oncomplete = hash256Complete(expectedHex, resultsArray, vectorArray.length);
        cryptoOp.onerror = function (e) { ok(false, "Error: " + e.message); };

        if (process) {
            var sections = partitionData(dataBytes);
            for (var j = 0; j < sections.length; j++) {
                cryptoOp.process(sections[j]);
            }
            cryptoOp.finish();
        }
    }
};

// #region SHA-224

module("SHA-224");

asyncTest("SHA-224 vectors short", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", false, false);

});

asyncTest("SHA-224 vectors short process sync", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", true, true);

});

asyncTest("SHA-224 vectors short process async", function () {

    aesVectorTest(testVectorsSha224Short, hash256Results, "sha-224", false, true);

});

asyncTest("SHA-224 vectors long", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", false, false);

});

asyncTest("SHA-224 vectors long process sync", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", true, true);

});

asyncTest("SHA-224 vectors long process async", function () {

    aesVectorTest(testVectorsSha224Long, hash256Results, "sha-224", false, true);

});

// #endregion SHA-224

// #region SHA-256

module("SHA-256");

asyncTest("SHA-256 vectors short", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", false, false);

});

asyncTest("SHA-256 vectors short process sync", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", true, true);

});

asyncTest("SHA-256 vectors short process async", function () {

    aesVectorTest(testVectorsSha256Short, hash256Results, "sha-256", false, true);

});

asyncTest("SHA-256 vectors long", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", false, false);

});

asyncTest("SHA-256 vectors long process sync", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", true, true);

});

asyncTest("SHA-256 vectors long process async", function () {

    aesVectorTest(testVectorsSha256Long, hash256Results, "sha-256", false, true);

});

// #endregion SHA-256



