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
/* global rsaShared */

/* jshint -W016 */

/// <dictionary>emsa,rsa,Struct,utils,octect</dictionary>

/// <disable>DeclareVariablesBeforeUse, DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

/// <disable>JS3085.VariableDeclaredMultipleTimes</disable>
var rsaMode = rsaMode || {};
/// <enable>JS3085.VariableDeclaredMultipleTimes</enable>

rsaMode.pss = function (keyStruct, hashFunction) {

    var utils = msrcryptoUtilities,
        random = msrcryptoPseudoRandom;

    function emsa_pss_encode(messageBytes) {

        var emBits = (keyStruct.n.length * 8) - 1;

        var emLen = Math.ceil(emBits / 8);

        //// checkMessageVsMaxHash(messageBytes);

        var /*@type(Array)*/ mHash = hashFunction.computeHash(messageBytes);

        var sLen = mHash.length;

        if (emLen < (mHash.length + sLen + 2)) {
            throw new Error("encoding error");
        }

        var /*@type(Array)*/ salt = random.getBytes(sLen);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [0, 0, 0, 0, 0, 0, 0, 0].concat(mHash, salt);

        var /*@type(Array)*/ h = hashFunction.computeHash(mp);

        var /*@type(Array)*/ ps = utils.getVector(emLen - salt.length - h.length - 2);

        var /*@type(Array)*/ db = ps.concat([1], salt);

        var /*@type(Array)*/ dbMask = rsaShared.mgf1(h, emLen - h.length - 1, hashFunction);

        var /*@type(Array)*/ maskedDb = utils.xorVectors(db, dbMask);

        // Set the ((8 * emLen) - emBits) of the leftmost octect in maskedDB to zero
        var mask = 0;
        for (var i = 0; i < 8 - ((8 * emLen) - emBits) ; i++) {
            mask += 1 << i;
        }
        maskedDb[0] &= mask;

        var em = maskedDb.concat(h, [0xbc]);

        return em;
    }

    function emsa_pss_verify( /*@type(Array)*/ signatureBytes,/*@type(Array)*/ messageBytes) {

        var emBits = (keyStruct.n.length * 8) - 1;

        var emLen = Math.ceil(emBits / 8);

        //// checkMessageVsMaxHash(messageBytes);

        var mHash = hashFunction.computeHash(messageBytes);

        var sLen = hashFunction.hashLen / 8;

        var hLen = hashFunction.hashLen / 8;

        if (emLen < (hLen + sLen + 2)) {
            return false;
        }

        var maskedDb = signatureBytes.slice(0, emLen - hLen - 1);

        var h = signatureBytes.slice(maskedDb.length, maskedDb.length + hLen);

        var dbMask = rsaShared.mgf1(h, emLen - hLen - 1, hashFunction);

        var /*@type(Array)*/ db = utils.xorVectors(maskedDb, dbMask);

        // Set the leftmost 8 * emLen - emBits of db[0] to zero
        db[0] &= 0xFF >>> (8 - ((8 * emLen) - emBits));

        // Verify the leftmost bytes are zero
        for (var i = 0; i < (emLen - hLen - sLen - 2) ; i++) {
            if (db[i] !== 0) {
                return false;
            }
        }

        if (db[emLen - hLen - sLen - 2] !== 0x01) {
            return false;
        }

        var salt = db.slice( -sLen);

        // M' = (0x) 00 00 00 00 00 00 00 00 || mHash || salt
        var mp = [0, 0, 0, 0, 0, 0, 0, 0].concat(mHash, salt);

        var hp = hashFunction.computeHash(mp);

        return utils.arraysEqual(hp, h);
    }

    return {

        sign: function (messageBytes) {
            return emsa_pss_encode(messageBytes);
        },

        verify: function (signatureBytes, messageBytes) {
            return emsa_pss_verify(signatureBytes, messageBytes);
        }
    };
};