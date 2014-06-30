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
/* global msrcryptoJwk */
/* global operations */
/* global msrcryptoUtilities */
/* global msrcryptoBlockCipher */
/* jshint -W016 */ /* allows bitwise operators */

/// <reference path="random.js" />
/// <reference path="utilities.js" />
/// <reference path="operations.js" />
/// <reference path="jwk.js" />
/// <reference path="aes.js" />

/// <dictionary>
///     Cbc,msrcrypto,res
/// </dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoPadding = msrcryptoPadding || {};

msrcryptoPadding.pkcsv7 = function (message, blockSize) {

    /// <summary>apply PKCS7 padding to message, which is updated</summary>
    /// <param name="message" type="Array"></param>
    /// <param name="blockSize" type="Number"></param>
    /// <returns></returns>
    var lastIndex = message.length - 1 >= 0 ? message.length - 1 : 0,
        lastBlock = message[lastIndex],
        lastBlockLength = lastBlock.length,
        createNewBlock = (lastBlockLength === blockSize);

    if (createNewBlock) {
        var newBlock = [], i;
        for (i = 0 ; i < blockSize; i += 1) {
            newBlock.push(blockSize);
        }
        message.push(newBlock);
    } else {
        var byteToAdd = (blockSize - lastBlockLength) & 0xff;
        while (lastBlock.length !== blockSize) {
            lastBlock.push(byteToAdd);
        }
    }
};

var msrcryptoCbc = function (blockCipher) {

    var blockSize = blockCipher.blockSize / 8;

    var paddingScheme = msrcryptoPadding.pkcsv7;

    // Merges an array of block arrays into a single byte array
    var mergeBlocks = function (/*@type(Array)*/tab) {
        var res = [], i, j;
        for (i = 0 ; i < tab.length; i += 1) {
            var block = tab[i];
            for (j = 0 ; j < block.length; j += 1) {
                res.push(block[j]);
            }
        }
        return res;
    };

    // Breaks an array of bytes into an array of block size arrays of bytes
    function getBlocks(dataBytes) {

        var blocks = [];

        // Append incoming bytes to the end of the existing buffered bytes
        mBuffer = mBuffer.concat(dataBytes);

        var blockCount = Math.floor(mBuffer.length / blockSize);

        for (var i = 0; i < blockCount; i++) {
            blocks.push(mBuffer.slice(i * blockSize, (i + 1) * blockSize));
        }

        // Set the buffer to the remaining bytes
        mBuffer = mBuffer.slice(blockCount * blockSize);

        return blocks;
    }

    function encryptBlocks(blocks) {

        var result = [],
            toEncrypt;

        for (var i = 0; i < blocks.length; i++) {
            toEncrypt = msrcryptoUtilities.xorVectors(mIvBytes, blocks[i]);
            result.push(blockCipher.encrypt(toEncrypt));
            mIvBytes = result[i];
        }

        return result;
    }

    function decryptBlocks(blocks) {

        var result = [],
            toDecrypt,
            decrypted;

        for (var i = 0 ; i < blocks.length; i += 1) {
            toDecrypt = blocks[i].slice(0, blocks[i].length);
            decrypted = blockCipher.decrypt(toDecrypt);
            result.push(msrcryptoUtilities.xorVectors(mIvBytes, decrypted));
            mIvBytes = blocks[i];
        }

        return result;
    }

    function clearState() {
        mBuffer = [];
        mResultBuffer = [];
        mIvBytes = null;
    }

    var mBuffer = [],
        mResultBuffer = [],
        mIvBytes;

    return {

        init: function (ivBytes) {

            if (ivBytes.length !== blockSize) {
                throw new Error("Invalid iv size");
            }

            mIvBytes = ivBytes.slice();
        },

        // Does a full encryption of the input
        encrypt: function (plainBytes) {
            /// <summary>perform the encryption of the plain text message</summary>
            /// <param name="plainBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            this.processEncrypt(plainBytes);

            return this.finishEncrypt();
        },

        // Encrypts full blocks of streamed input
        processEncrypt: function (plainBytes) {

            var result = encryptBlocks(getBlocks(plainBytes));

            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return;
        },

        // Call when done streaming input
        finishEncrypt: function () {

            var blocks = mBuffer.length === 1 ? [[mBuffer[0]]] : [mBuffer];

            paddingScheme(blocks, blockSize);

            var result = mResultBuffer.concat(mergeBlocks(encryptBlocks(blocks)));

            clearState();

            return result;
        },

        // Does a full decryption and returns the result
        decrypt: function (/*@type(Array)*/cipherBytes) {
            /// <summary>perform the decryption of the encrypted message</summary>
            /// <param name="encryptedBytes" type="Array">the plain text to encrypt</param>
            /// <returns type="Array">the encrypted message</returns>

            this.processDecrypt(cipherBytes);

            return this.finishDecrypt();
        },

        // Decrypts full blocks of streamed data
        processDecrypt: function (cipherBytes) {

            var result = decryptBlocks(getBlocks(cipherBytes));

            mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

            return;
        },

        // Called to finalize streamed decryption
        finishDecrypt: function () {

            var result = mResultBuffer;

            // Strip the padding.
            // Read the last element and strip off that many elements from the end.
            result = result.slice(0, result[result.length - 1] * -1);

            clearState();

            return result;
        }

    };
};

var cbcInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoCbc.workerEncrypt = function (p) {

        var result;

        if (!cbcInstance) {
            cbcInstance = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstance.init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            cbcInstance.processEncrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = cbcInstance.finishEncrypt();
            cbcInstance = null;
            return result;
        }

        result = cbcInstance.encrypt(p.buffer);
        cbcInstance = null;
        return result;
    };

    msrcryptoCbc.workerDecrypt = function (p) {

        var result;

        if (!cbcInstance) {
            cbcInstance = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
            cbcInstance.init(p.algorithm.iv);
        }

        if (p.operationSubType === "process") {
            cbcInstance.processDecrypt(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            result = cbcInstance.finishDecrypt();
            cbcInstance =  null;
            return result;
        }

        result = cbcInstance.decrypt(p.buffer);
        cbcInstance =  null;
        return result;
    };

    msrcryptoCbc.generateKey = function (p) { 

        if (p.algorithm.length % 8 !== 0) {
            throw new Error();
        }

        return {
            type: "keyGeneration",
            keyData: msrcryptoPseudoRandom.getBytes(Math.floor(p.algorithm.length / 8)),
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoCbc.importKey = function (p) { 

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);

        return {
            type: "keyImport",
            keyData: keyObject.k,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage,
                type: "secret"
            }
        };
    };

    msrcryptoCbc.exportKey = function (p) { 

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };
    };

    operations.register("importKey", "aes-cbc", msrcryptoCbc.importKey);
    operations.register("exportKey", "aes-cbc", msrcryptoCbc.exportKey);
    operations.register("generateKey", "aes-cbc", msrcryptoCbc.generateKey);
    operations.register("encrypt", "aes-cbc", msrcryptoCbc.workerEncrypt);
    operations.register("decrypt", "aes-cbc", msrcryptoCbc.workerDecrypt);
}