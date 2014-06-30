﻿//*********************************************************
//
//    Copyright (c) Microsoft. All rights reserved.
//
//    THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
//    ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
//    IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
//    PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
//
//*********************************************************

/// #region JSCop/JsHint

/* global operations */
/* global msrcryptoUtilities */
/* global msrcryptoSha256 */
/* global msrcryptoSha512 */
/* global msrcryptoSha1 */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="sha256.js " />
/// <reference path="sha512.js " />

/// <dictionary>alg,Func,Kdf,msrcrypto,utils</dictionary>

/// <disable>DeclareVariablesBeforeUse,DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

/// The "concat" key derivation function from NIST SP-800-56A.
var msrcryptoKdf = function (hashFunction) {

    var utils = msrcryptoUtilities;

    function deriveKey(/*type(Array)*/ secretBytes, /*type(Array)*/ otherInfo, keyOutputLength) {

        var reps = Math.ceil(keyOutputLength / (hashFunction.hashLen / 8)),
            counter = 1,
            digest = secretBytes.concat(otherInfo),
            output = [];

        for (var i = 0; i < reps; i++) {

            var data = utils.int32ToBytes(counter++).concat(digest);

            var /*type(Array)*/ h = hashFunction.computeHash(data);

            output = output.concat(h);
        }

        return output.slice(0, keyOutputLength);
    }

    return {

        deriveKey: deriveKey

    };

};

var msrcryptoKdfInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoKdf.deriveKey = function (/*@dynamic*/p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash;

        var hashFunction = msrcryptoHashFunctions[hashName.toLowerCase()];

        msrcryptoKdfInstance = msrcryptoKdf(hashFunction);

        var alg = p.algorithm;

        var otherInfo =
            alg.algorithmId.concat(
            alg.partyUInfo,
            alg.partyVInfo,
            alg.publicInfo || [],
            alg.privateInfo || []);

        var result =
            msrcryptoKdfInstance.deriveKey(p.keyData, otherInfo, p.derivedKeyType.length);

        msrcryptoKdfInstance = null;

        return {
            type: "keyDerive",
            keyData: result,
            keyHandle: {
                algorithm: p.derivedKeyType,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };

    };

    msrcryptoKdf.deriveBits = function (/*@dynamic*/p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash;

        var hashFunction = msrcryptoHashFunctions[hashName.toLowerCase()];

        msrcryptoKdfInstance = msrcryptoKdf(hashFunction);

        var alg = p.algorithm;

        var otherInfo =
            alg.algorithmId.concat(
            alg.partyUInfo,
            alg.partyVInfo,
            alg.publicInfo || [],
            alg.privateInfo || []);

        var result =
            msrcryptoKdfInstance.deriveKey(p.keyData, otherInfo, p.length);

        msrcryptoKdfInstance = null;

        return result;

    };

    operations.register("deriveKey", "concat", msrcryptoKdf.deriveKey);
    operations.register("deriveBits", "concat", msrcryptoKdf.deriveBits);

}