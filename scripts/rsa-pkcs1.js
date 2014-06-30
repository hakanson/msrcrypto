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

/// #region JSCop/JsHint

/* global msrcryptoPseudoRandom */
/* global msrcryptoUtilities */

/* jshint -W016 */

/// <reference path="utilities.js " />
/// <reference path="random.js " />

/// <dictionary>emp,emsa,pkcs,rsa,Struct,tlen,unpad,utils</dictionary>

/// <disable></disable>

/// #endregion JSCop/JsHint

var rsaMode = rsaMode || {};

rsaMode.pkcs1Encrypt = function (keyStruct) {

    var random = msrcryptoPseudoRandom,
        size = keyStruct.n.length;

    function pad(data) {

        var randomness;

        if (data.length > size - 11) {
            throw new Error("message too long");
        }

        // A minimum of 8 random bytes
        randomness = random.getNonZeroBytes(size - data.length - 3);

        return [0, 2].concat(randomness, [0], data);
    }

    function unpad(paddedData) {
        var i;

        for (i = 1; i < paddedData.length; i += 1) {
            if (paddedData[i] === 0) {
                break;
            }
        }

        return paddedData.slice(i + 1);
    }

    return {

        pad: function (messageBytes) {
            return pad(messageBytes);
        },

        unpad: function (encodedBytes) {
            return unpad(encodedBytes);
        }
    };

};

rsaMode.pkcs1Sign = function (keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        size = keyStruct.n.length;

    function emsa_pkcs1_v15_encode(messageBytes) {

        var paddedData,
            hash,
            tlen;

        hash = hashFunction.computeHash(messageBytes.slice());

        paddedData = hashFunction.der.concat(hash);

        tlen = paddedData.length;

        if (size < tlen + 11) {
            throw new Error("intended encoded message length too short");
        }

        return [0x00, 0x01].concat(
            utils.getVector(size - tlen - 3, 0xFF),
            [0],
            paddedData);
    }

    return {

        sign: function (messageBytes) {
            return emsa_pkcs1_v15_encode(messageBytes);
        },

        verify: function (signatureBytes, messageBytes) {
            var emp = emsa_pkcs1_v15_encode(messageBytes);

            return utils.arraysEqual(signatureBytes, emp);
        }
    };
};
