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

/// <reference path="utilities.js" />
/// <reference path="cryptoMath.js" />
/// <reference path="cryptoECC.js" />
/// <reference path="sha256.js" />
/// <reference path="sha512.js" />

/* global operations */
/* global msrcryptoHashFunctions */
/* global cryptoMath */
/* global cryptoECC */
/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */

/* jshint -W016 */

/// <dictionary>btd,dtb,Ecdsa,ecop,msrcrypto</dictionary>

/// <disable>DeclareVariablesBeforeUse,DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoEcdsa = function (curve) {

    var btd = cryptoMath.bytesToDigits,
        dtb = cryptoMath.digitsToBytes,
        ecop = new cryptoECC.EllipticCurveOperatorFp(curve);

    function createKey(privateKeyBytes) {
        return createKeyInternal(btd(privateKeyBytes));
    }

    function createKeyInternal(privateKeyDigits) {

        if (!curve.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(curve.generator);
        }

        var publicKey = curve.allocatePointStorage();
        ecop.convertToJacobianForm(publicKey);
        ecop.convertToMontgomeryForm(publicKey);
        ecop.scalarMultiply(privateKeyDigits, curve.generator, publicKey);

        ecop.convertToAffineForm(publicKey);
        ecop.convertToStandardForm(publicKey);

        return {
            publicKey: publicKey,
            privateKey: privateKeyDigits
        };
    }

    function generateKey() {

        var privateKey = [],
            randomBytes = msrcryptoPseudoRandom.getBytes(
                curve.order.length * cryptoMath.DIGIT_NUM_BYTES);

        cryptoMath.reduce(
            cryptoMath.bytesToDigits(randomBytes),
            curve.order,
            privateKey);

        if (!curve.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(curve.generator);
        }

        return createKeyInternal(privateKey);
    }

    function sign(privateKey, messageBytes, /*@optional*/ ephemeralKey) {

        if (!ephemeralKey) {
            do {
                ephemeralKey = generateKey();
            } while (cryptoMath.isZero(ephemeralKey.publicKey.x) ||
                cryptoMath.compareDigits(curve.order, ephemeralKey.publicKey.x) === 0);
        }

        if (!ephemeralKey.publicKey) {
            throw new Error("ephemeralKey.publicKey missing");
        }

        if (!ephemeralKey.privateKey) {
            throw new Error("ephemeralKey.privateKey missing");
        }

        var r = ephemeralKey.publicKey.x;
        var k = ephemeralKey.privateKey;

        var d = btd(privateKey.d);
        var s = [], tmp = [];

        cryptoMath.modMul(r, d, curve.order, s);
        cryptoMath.add(s, btd(messageBytes), s);
        cryptoMath.reduce(s, curve.order, s);

        cryptoMath.modInv(k, curve.order, tmp);
        cryptoMath.modMul(s, tmp, curve.order, s);

        var signature = dtb(r).concat(dtb(s));

        return signature;
    }

    function verify(publicKey, signatureBytes, messageBytes) {

        var split = Math.floor(signatureBytes.length / 2),
            r = btd(signatureBytes.slice(0, split)),
            s = btd(signatureBytes.slice(split)),
            digest = btd(messageBytes),
            u1 = [],
            u2 = [];

        var publicPoint = new cryptoECC.EllipticCurvePointFp(
            curve, false, btd(publicKey.x), btd(publicKey.y), null, false);

        cryptoMath.modInv(s, curve.order, s);
        cryptoMath.modMul(digest, s, curve.order, u1);

        cryptoMath.modMul(r, s, curve.order, u2);

        var r0 = curve.allocatePointStorage();
        ecop.convertToJacobianForm(r0);
        ecop.convertToMontgomeryForm(r0);

        if (!curve.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(curve.generator);
        }

        if (!curve.generator.isAffine) {
            ecop.convertToStandardForm(curve.generator);
        }

        ecop.scalarMultiply(u1, curve.generator, r0);

        var r1 = curve.allocatePointStorage();
        ecop.convertToJacobianForm(r1);
        ecop.convertToMontgomeryForm(r1);

        ecop.convertToMontgomeryForm(publicPoint);

        ecop.scalarMultiply(u2, publicPoint, r1);
        ecop.convertToAffineForm(r1);
        ecop.mixedAdd(r0, r1, r0);

        ecop.convertToAffineForm(r0);
        ecop.convertToStandardForm(r0);

        if (r0.isInfinity) {
            return false;
        }

        if (cryptoMath.compareDigits(r0.x, r) === 0) {
            return true;
        }

        return false;
    }

    return {
        createKey: createKey,
        generateKey: generateKey,
        sign: sign,
        verify: verify
    };

};

if (typeof operations !== "undefined") {

    msrcryptoEcdsa.curves = {
        "p-256": cryptoECC.createP256,
        "p-384": cryptoECC.createP384
    };

    msrcryptoEcdsa.sign = function ( /*@dynamic*/ p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash,
            curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve](),
            hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()],
            digest = hashFunc.computeHash(p.buffer);

        var ecdsa = msrcryptoEcdsa(curve);

        return ecdsa.sign(p.keyData, digest);
    };

    msrcryptoEcdsa.verify = function ( /*@dynamic*/ p) {

        var hashName = p.algorithm.hash.name || p.algorithm.hash,
            curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve](),
            hashFunc = msrcryptoHashFunctions[hashName.toLowerCase()],
            digest = hashFunc.computeHash(p.buffer);

        var ecdsa = msrcryptoEcdsa(curve);

        return ecdsa.verify(p.keyData, p.signature, digest);
    };

    msrcryptoEcdsa.generateKey = function (p) {

        var curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve]();

        var ecdsa = msrcryptoEcdsa(curve);

        var keyPairData = ecdsa.generateKey();

        var dtb = cryptoMath.digitsToBytes;

        return {
            type: "keyPairGeneration",
            keyPair: {
                publicKey: {
                    keyData: {
                        x: dtb(keyPairData.publicKey.x),
                        y: dtb(keyPairData.publicKey.y)
                    },
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: null || p.keyUsage,
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: {
                        x: dtb(keyPairData.publicKey.x),
                        y: dtb(keyPairData.publicKey.y),
                        d: dtb(keyPairData.privateKey)
                    },
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: null || p.keyUsage,
                        type: "private"
                    }
                }
            }
        };

    };

    msrcryptoEcdsa.importKey = function (p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["x", "y", "d", "crv"]);

        // If only private key data 'd' is imported, create x and y
        if (keyObject.d && (!keyObject.x || !keyObject.y)) {

            var curve = msrcryptoEcdsa.curves[p.algorithm.namedCurve]();

            var ecdsa = msrcryptoEcdsa(curve);

            var publicKey = ecdsa.computePublicKey(keyObject.d);

            keyObject.x = publicKey.x;
            keyObject.y = publicKey.y;
        }

        return {
            type: "keyImport",
            keyData: keyObject,
            keyHandle: {
                algorithm: p.algorithm,
                extractable: p.extractable || keyObject.extractable,
                keyUsage: null || p.keyUsage, // IE11 returns null here
                type: (keyObject.d) ? "private" : "public"
            }
        };
    };

    msrcryptoEcdsa.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };

    };

    operations.register("sign", "ecdsa", msrcryptoEcdsa.sign);

    operations.register("verify", "ecdsa", msrcryptoEcdsa.verify);

    operations.register("generateKey", "ecdsa", msrcryptoEcdsa.generateKey);

    operations.register("importKey", "ecdsa", msrcryptoEcdsa.importKey);

    operations.register("exportKey", "ecdsa", msrcryptoEcdsa.exportKey);

}