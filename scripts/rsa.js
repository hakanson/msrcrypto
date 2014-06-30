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

/* global msrcryptoRsaBase */
/* global rsaMode */
/* global operations */
/* global msrcryptoJwk */
/* global msrcryptoSha256 */
/* global msrcryptoSha512 */
/* global msrcryptoSha1 */

/* jshint -W016 */

/// <dictionary>Func,msrcrypto,Obj,Rsa,Struct,unpad</dictionary>

/// <disable>DeclareVariablesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoRsa = function (keyStruct, paddingMode, /*@optional*/ hashFunction) {

    var rsaBase = msrcryptoRsaBase(keyStruct);

    if (!paddingMode) {
        throw new Error("padding mode");
    }

    if (!hashFunction) {
        hashFunction = msrcryptoSha256.sha256;
    }

    var paddingFunction = null,
        unPaddingFunction = null;

    var padding;

    switch (paddingMode) {

        case "rsaes-pkcs1-v1_5":
            padding = rsaMode.pkcs1Encrypt(keyStruct, hashFunction);
            break;

        case "rsassa-pkcs1-v1_5":
            padding = rsaMode.pkcs1Sign(keyStruct, hashFunction);
            break;

        case "rsa-oaep":
            padding = rsaMode.oaep(keyStruct, hashFunction);
            break;

        case "rsa-pss":
            padding = rsaMode.pss(keyStruct, hashFunction);
            break;

        case "raw":
            padding = {
                pad: function (mb) { return mb; },
                unpad: function (eb) { return eb; }
            };
            break;

        default:
            throw new Error("invalid padding mode");
    }

    if (padding) {
        paddingFunction = padding.pad || padding.sign;
        unPaddingFunction = padding.unpad || padding.verify;
    }

    var returnObj = {

        encrypt: function (/*@type(Array)*/ dataBytes, /*@optional*/ labelBytes) {

            var paddedData;

            if (paddingFunction !== null) {
                // OAEP padding can take two arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                paddedData = paddingFunction(dataBytes, labelBytes);
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            } else {
                // Slice() has optional arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                paddedData = dataBytes.slice();
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            }

            return rsaBase.encrypt(paddedData);
        },

        decrypt: function (/*@type(Array)*/ cipherBytes, /*@optional*/ labelBytes) {

            var /*@type(Array)*/ decryptedData = rsaBase.decrypt(cipherBytes);

            if (unPaddingFunction !== null) {
                // OAEP padding can take two arguments
                ///<disable>JS3053.IncorrectNumberOfArguments</disable>
                decryptedData = unPaddingFunction(decryptedData, labelBytes);
                ///<enable>JS3053.IncorrectNumberOfArguments</enable>
            } else {
                decryptedData = decryptedData.slice(0);
            }

            return decryptedData;
        },

        signData: function (/*@type(Array)*/ messageBytes) {

            return rsaBase.decrypt(paddingFunction(messageBytes));
        },

        verifySignature: function (/*@type(Array)*/ signature, /*@type(Array)*/ messageBytes) {

            var decryptedSig = rsaBase.encrypt(signature);

            return unPaddingFunction(decryptedSig, messageBytes);
        },

        paddingMode: paddingMode
    };

    return returnObj;
};

if (typeof operations !== "undefined") {

    msrcryptoRsa.sign = function ( /*@dynamic*/ p) {

        var rsaObj,
            hashFunc,
            hashName = p.algorithm.hash.name || p.algorithm.hash;

        hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()];

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.signData(p.buffer);
    };

    msrcryptoRsa.verify = function ( /*@dynamic*/ p) {

        var hashFunc,
            hashName = p.algorithm.hash.name || p.algorithm.hash,
            rsaObj;

        hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()];

        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

        return rsaObj.verifySignature(p.signature, p.buffer);
    };

    msrcryptoRsa.workerEncrypt = function ( /*@dynamic*/ p) {

        var result,
            rsaObj,
            hashFunc;

        switch (p.algorithm.name) {

            case "rsaes-pkcs1-v1_5":
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                result = rsaObj.encrypt(p.buffer);
                break;

            case "rsa-oaep":
                var hashName = p.algorithm.hash.name || p.algorithm.hash;
                if (!hashName) {
                    throw new Error("unsupported hash algorithm");
                }
                hashFunc = msrcryptoHashFunctions[hashName];
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                result = rsaObj.encrypt(p.buffer);
                break;

            default:
                throw new Error("unsupported algorithm");
        }

        return result;
    };

    msrcryptoRsa.workerDecrypt = function ( /*@dynamic*/ p) {

        var result,
            rsaObj,
            hashFunc;

        switch (p.algorithm.name) {

            case "rsaes-pkcs1-v1_5":
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                result = rsaObj.decrypt(p.buffer);
                break;

            case "rsa-oaep":
                switch (p.algorithm.hash.name || p.algorithm.hash) {
                    case "sha-384":
                        hashFunc = msrcryptoSha512.sha384;
                        break;
                    case "sha-512":
                        hashFunc = msrcryptoSha512.sha512;
                        break;
                    case "sha-1":
                        hashFunc = msrcryptoSha1.sha1;
                        break;
                    default:
                        hashFunc = msrcryptoSha256.sha256;
                        break;
                }
                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                result = rsaObj.decrypt(p.buffer);
                break;

            default:
                throw new Error("unsupported algorithm");
        }

        return result;
    };

    msrcryptoRsa.importKey = function ( /*@dynamic*/ p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["n", "e", "d", "q", "p", "dq", "dp", "qi"]);

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage, // IE11 returns null here
                type: (keyObject.d || keyObject.dq) ? "private" : "public"
            }
        };
    };

    msrcryptoRsa.exportKey = function ( /*@dynamic*/ p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("sign", "rsassa-pkcs1-v1_5", msrcryptoRsa.sign);
    operations.register("sign", "rsa-pss", msrcryptoRsa.sign);

    operations.register("verify", "rsassa-pkcs1-v1_5", msrcryptoRsa.verify);
    operations.register("verify", "rsa-pss", msrcryptoRsa.verify);

    operations.register("encrypt", "rsa-oaep", msrcryptoRsa.workerEncrypt);
    operations.register("encrypt", "rsaes-pkcs1-v1_5", msrcryptoRsa.workerEncrypt);

    operations.register("decrypt", "rsa-oaep", msrcryptoRsa.workerDecrypt);
    operations.register("decrypt", "rsaes-pkcs1-v1_5", msrcryptoRsa.workerDecrypt);

    operations.register("importKey", "rsa-oaep", msrcryptoRsa.importKey);
    operations.register("importKey", "rsaes-pkcs1-v1_5", msrcryptoRsa.importKey);
    operations.register("importKey", "rsassa-pkcs1-v1_5", msrcryptoRsa.importKey);
    operations.register("importKey", "rsa-pss", msrcryptoRsa.importKey);

    operations.register("exportKey", "rsa-oaep", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsaes-pkcs1-v1_5", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsassa-pkcs1-v1_5", msrcryptoRsa.exportKey);
    operations.register("exportKey", "rsa-pss", msrcryptoRsa.exportKey);

}