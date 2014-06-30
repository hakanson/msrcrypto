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
/// <reference path="~/scripts/utilities.js" />

var utils = msrcryptoUtilities;

var entropy = [];
for (var i = 0; i < 48; i += 1) {
    entropy[i] = Math.floor(Math.random() * 256);
}

// init the prng with the entropy
msrCrypto.initPrng(entropy);

var typedArraySupport = (typeof Uint8Array !== "undefined");

function isTypedArray(array) {
    return (Object.prototype.toString.call(array) === "[object Uint8Array]");
}

function textToBytes(text) {

    var result = newArray(text.length);

    for (var i = 0; i < result.length; i++) {
        result[i] = text.charCodeAt(i);
    }

    return result;
}

function getArrayResult(value) {

    if (Object.prototype.toString.call(value).slice(8, -1) === "ArrayBuffer") {
        var uint8 = new Uint8Array(value);
        return (uint8.length === 1) ? [uint8[0]] : Array.apply(null, uint8);
    }

    return value;

}

function bytesToHexString(bytes) {
    var result = "";

    for (var i = 0 ; i < bytes.length; i++) {

        if (i % 4 == 0 && i != 0) result += "-";

        var hexval = bytes[i].toString(16).toUpperCase();
        // add a leading zero if needed
        if (hexval.length == 1)
            result += "0";

        result += hexval;
    }

    return result;
}

function keyTextToKeyData(keyType, keyText) {

    switch (keyType) {
        case "aes":
            return textToBytes('{"kty": "oct", "k": "' + keyText + '", "extractable": true  }');

        case "hmac":
            return textToBytes('{"kty" : "oct", "alg" : "HS256", "k" : "' + keyText + '", "extractable" : true }');

        case "rsa":
            return textToBytes(keyText);

        default:
            throw new Error("invalid key type");
    }

}

function hexToBytesArray(hexString) {

    hexString = hexString.replace(/[^A-Fa-f0-9]/g, "");

    var result = [];
    while (hexString.length >= 2) {
        result.push(parseInt(hexString.substring(0, 2), 16));
        hexString = hexString.substring(2, hexString.length);
    }

    return toSupportedArray(result);
}

function toSupportedArray(dataArray) {

    //already typed array and hence supported
    if (isTypedArray(dataArray)) {
        return dataArray;
    }

    //convert to typed array
    if (typedArraySupport) {
        return new Uint8Array(dataArray);
    }

    //typed arrays not suppored
    return dataArray;

}

function newArray(size) {

    if (typedArraySupport) {
        return new Uint8Array(size);
    }
    return new Array(size);
}

function slice(array, start, end) {

    if (typedArraySupport) {
        return array.subarray(start, end);
    }
    return array.slice(start, end);
}

function partitionData(dataArray) {

    var result = [];
    var i = 0;

    while (i < dataArray.length) {
        var randomnumber = Math.floor(Math.random() * dataArray.length + 1) + i;
        result.push(slice(dataArray, i, randomnumber));
        i = randomnumber;
    }

    return result;
}

function importKey(keyType, keyData, callback, errorCallback, callbackParams) {

    var keyOp = null;

    if (keyType == 'hmac') {
        keyOp = subtle.importKey("jwk", keyData, { name: "hmac", hash: { name: "sha-256" } }, true, []);

    } else if (keyType == 'aes-cbc') {
        keyOp = subtle.importKey("jwk", keyData, { name: "aes-cbc" }, true, []);

    } else if (keyType == 'aes-gcm') {
        keyOp = subtle.importKey("jwk", keyData, { name: "aes-gcm" }, true, []);

    } else {
        throw new Error("invalid keyType");
    }

    keyOp.oncomplete = function (e) {
        callback(e.target.result, callbackParams);
    };

    keyOp.onerror = function (e) {
        errorCallback(e);
    };

    return;
}

function importKeyBytes(keyType, keyBytes, callback, errorCallback, callbackParams) {

    //convert from bytes ==> string ==> straight Base64 ==> Base64Url
    var keyText = msrCrypto.stringToBase64(keyBytes, true);

    var keyData = keyTextToKeyData("hmac", keyText);

    importKey(keyType, keyData, callback, errorCallback, callbackParams);

    return;
}

function flip(percent) {

    if (percent > 1) {
        percent = (percent / 100);
    }
    return (Math.random() > percent);
}

function hexStringToBase64Url(hexString) {
    var bytes = msrcryptoUtilities.hexToBytesArray(hexString);
    var b64Url = msrCrypto.stringToBase64(bytes);
    return b64Url.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
}

function error(e) {
    start();
    ok(false, "Crypto Error");
}

function setAsyncState(state) {

    if (state) {
        subtle.forceSync = true;
    }

    if (Math.random() >= 0.5) {
        subtle.forceSync = false;
    } else {
        (subtle.forceSync !== undefined) && delete subtle.forceSync;
    }

}

function base64UrlToBytes(base64UrlText) {

    return textToBytes(msrCrypto.base64ToString(base64UrlText));
}

function getKeyData(keyHandle, callback, callbackParam) {

    var keyOpExp = subtle.exportKey("jwk", keyHandle, true, []);

    keyOpExp.oncomplete = function (e) {

        // Decode the exported key
        var keyBytes = getArrayResult(e.target.result);
        var keyString = String.fromCharCode.apply(null, keyBytes);
        var keyObject = JSON.parse(keyString);

        callback(keyObject, callbackParam);
    }
}

var hexToBytes = msrcryptoUtilities.hexToBytesArray;

