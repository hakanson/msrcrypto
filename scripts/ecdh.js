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

/* global operations */
/* global cryptoMath */
/* global cryptoECC */
/* global msrcryptoPseudoRandom */
/* global msrcryptoJwk */

/// <dictionary>btd,dtb,Ecdh,ecop,msrcrypto</dictionary>

/// <disable>DeclareVariablesBeforeUse</disable>

/// #endregion JSCop/JsHint

var msrcryptoEcdh = function (curve) {

    var btd = cryptoMath.bytesToDigits,
        dtb = cryptoMath.digitsToBytes,
        e = curve,
        ecop = new cryptoECC.EllipticCurveOperatorFp(curve);

    function generateKey() {

        var privateKey = [],
            randomBytes = msrcryptoPseudoRandom.getBytes(
                curve.order.length * cryptoMath.DIGIT_NUM_BYTES);

        cryptoMath.reduce(
            cryptoMath.bytesToDigits(randomBytes),
            e.order,
            privateKey);

        if (!e.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(e.generator);
        }

        var publicKey = e.allocatePointStorage();
        ecop.convertToJacobianForm(publicKey);
        ecop.convertToMontgomeryForm(publicKey);
        ecop.scalarMultiply(privateKey, e.generator, publicKey);

        return {
            privateKey: {
                x: dtb(publicKey.x),
                y: dtb(publicKey.y),
                d: dtb(privateKey)
            },
            publicKey: {
                x: dtb(publicKey.x),
                y: dtb(publicKey.y)
            }
        };
    }

    function deriveBits(privateKey, publicKey, length) {

        var publicPoint = new cryptoECC.EllipticCurvePointFp(
            e, false, btd(publicKey.x), btd(publicKey.y), null, false);

        if (!publicPoint.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(publicPoint);
        }

        if (!publicPoint.isAffine) {
            ecop.convertToAffineForm(publicPoint);
        }

        var sharedSecretPoint = e.allocatePointStorage();
        ecop.convertToJacobianForm(sharedSecretPoint);
        ecop.convertToMontgomeryForm(sharedSecretPoint);

        ecop.scalarMultiply(btd(privateKey.d), publicPoint, sharedSecretPoint);

        ecop.convertToAffineForm(sharedSecretPoint);
        ecop.convertToStandardForm(sharedSecretPoint);

        var secretBytes = cryptoMath.digitsToBytes(sharedSecretPoint.x);

        if (length && secretBytes.length < length) {
            throw new Error("DataError");
        }

        return length ? secretBytes.slice(0, length) : secretBytes;
    }

    function computePublicKey(privateKeyBytes) {

        if (!e.generator.isInMontgomeryForm) {
            ecop.convertToMontgomeryForm(e.generator);
        }

        var publicKey = e.allocatePointStorage();
        ecop.convertToJacobianForm(publicKey);
        ecop.convertToMontgomeryForm(publicKey);
        ecop.scalarMultiply(btd(privateKeyBytes), e.generator, publicKey);

        return {
            x: dtb(publicKey.x),
            y: dtb(publicKey.y)
        };
    }

    return {

        generateKey: generateKey,
        deriveBits: deriveBits,
        computePublicKey: computePublicKey
    };

};

var ecdhInstance = null;

if (typeof operations !== "undefined") {

    msrcryptoEcdh.curves = {
        "P-256": cryptoECC.createP256,
        "P-384": cryptoECC.createP384,
        "P-521": cryptoECC.createP521
    };

    msrcryptoEcdh.deriveBits = function (p) {

        var curve = msrcryptoEcdh.curves[p.algorithm.namedCurve]();

        var privateKey = p.keyData;

        var publicKey = p.additionalKeyData;

        ecdhInstance = msrcryptoEcdh(curve);

        var secretBytes = ecdhInstance.deriveBits(privateKey, publicKey, p.length);

        return secretBytes;
    };

    msrcryptoEcdh.generateKey = function (p) {

        var curve = msrcryptoEcdh.curves[p.algorithm.namedCurve]();

        ecdhInstance = msrcryptoEcdh(curve);

        var keyPairData = ecdhInstance.generateKey();

        return {
            type: "keyPairGeneration",
            keyPair: {
                publicKey: {
                    keyData: keyPairData.publicKey,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        keyUsage: null || p.keyUsage,
                        type: "public"
                    }
                },
                privateKey: {
                    keyData: keyPairData.privateKey,
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

    msrcryptoEcdh.importKey = function (p) {

        var keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["x", "y", "d", "crv"]);

        // If only private key data 'd' is imported, create x and y
        if (keyObject.d && (!keyObject.x || !keyObject.y)) {

            var curve = msrcryptoEcdh.curves[p.algorithm.namedCurve]();

            ecdhInstance = msrcryptoEcdh(curve);

            var publicKey = ecdhInstance.computePublicKey(keyObject.d);

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

    msrcryptoEcdh.exportKey = function (p) {

        var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

        return { type: "keyExport", keyHandle: jsonKeyStringArray };

    };

    operations.register("importKey", "ecdh", msrcryptoEcdh.importKey);
    operations.register("exportKey", "ecdh", msrcryptoEcdh.exportKey);
    operations.register("generateKey", "ecdh", msrcryptoEcdh.generateKey);
    operations.register("deriveBits", "ecdh", msrcryptoEcdh.deriveBits);
}