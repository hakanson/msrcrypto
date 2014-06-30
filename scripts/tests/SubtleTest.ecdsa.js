/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.14.0.js" />

module("ECDSA");

function ecdsaError(message) {
    return function (e) {
        start();
        ok(false, message);
    }
}

asyncTest("GenerateKey P-256", function () {

    var algorithm = { name: "ecdsa", namedCurve: "p-256" };

    var keyGenOp = subtle.generateKey(algorithm);

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        getKeyData(keyPair.publicKey, function (publicKeyObject) {

            getKeyData(keyPair.privateKey, function (priKey, pubKey) {

                start();

                equal(keyPair.publicKey.type, "public");
                equal(keyPair.publicKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.publicKey.algorithm.namedCurve.toLowerCase(), "p-256");

                equal(pubKey.kty.toLowerCase(), "ec");
                equal(pubKey.crv.toLowerCase(), "p-256");
                equal(base64UrlToBytes(pubKey.x).length, 32);
                equal(base64UrlToBytes(pubKey.y).length, 32);

                equal(keyPair.privateKey.type, "private");
                equal(keyPair.privateKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.privateKey.algorithm.namedCurve.toLowerCase(), "p-256");

                equal(priKey.kty.toLowerCase(), "ec");
                equal(priKey.crv.toLowerCase(), "p-256");
                equal(base64UrlToBytes(priKey.d).length, 32);
                equal(base64UrlToBytes(priKey.x).length, 32);
                equal(base64UrlToBytes(priKey.y).length, 32);

            }, publicKeyObject);

        });

    }

    keyGenOp.onerror = ecdsaError("Generate key error");

});

asyncTest("GenerateKey P-384", function () {

    var algorithm = { name: "ecdsa", namedCurve: "p-384" };

    var keyGenOp = subtle.generateKey(algorithm);

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        getKeyData(keyPair.publicKey, function (publicKeyObject) {

            getKeyData(keyPair.privateKey, function (priKey, pubKey) {

                start();

                equal(keyPair.publicKey.type, "public");
                equal(keyPair.publicKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.publicKey.algorithm.namedCurve.toLowerCase(), "p-384");

                equal(pubKey.kty.toLowerCase(), "ec");
                equal(pubKey.crv.toLowerCase(), "p-384");
                equal(base64UrlToBytes(pubKey.x).length, 48);
                equal(base64UrlToBytes(pubKey.y).length, 48);

                equal(keyPair.privateKey.type, "private");
                equal(keyPair.privateKey.algorithm.name.toLowerCase(), "ecdsa");
                equal(keyPair.privateKey.algorithm.namedCurve.toLowerCase(), "p-384");

                equal(priKey.kty.toLowerCase(), "ec");
                equal(priKey.crv.toLowerCase(), "p-384");
                equal(base64UrlToBytes(priKey.d).length, 48);
                equal(base64UrlToBytes(priKey.x).length, 48);
                equal(base64UrlToBytes(priKey.y).length, 48);

            }, publicKeyObject);

        });

    }

    keyGenOp.onerror = ecdsaError("Generate key error");

});

asyncTest("Sign & Verify P-256 SHA-256", function () {



    var keyGenOp = subtle.generateKey({ name: "ecdsa", namedCurve: "p-256" });

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        var data = [];

        for (var j = 0; j < Math.random() * 300; j++) {
            data.push(Math.random() * 256);
        }

        var algorithm = { name: "ecdsa", namedCurve: "p-256", hash: { name: "sha-256" } };

        var cryptoOp = subtle.sign(algorithm, keyPair.privateKey, data);

        cryptoOp.oncomplete = function (e) {

            var signatureBytes = getArrayResult(e.target.result);

            var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data);

            opVerify.oncomplete = function (e) {

                var result = e.target.result;

                start();

                ok(result, "s = " + bytesToHexString(signatureBytes));
            }

            opVerify.onerror = ecdsaError("Verify error");

        }

        cryptoOp.onerror = ecdsaError("Sign error");

    }

    keyGenOp.onerror = ecdsaError("Generate key error");



});

asyncTest("Sign & Verify P-384 SHA-256", function () {

    var keyGenOp = subtle.generateKey({ name: "ecdsa", namedCurve: "p-384" });

    keyGenOp.oncomplete = function (e) {

        var keyPair = e.target.result;

        var data = [];

        for (var j = 0; j < Math.random() * 300; j++) {
            data.push(Math.random() * 256);
        }

        var algorithm = { name: "ecdsa", namedCurve: "p-384", hash: { name: "sha-256" } };

        var cryptoOp = subtle.sign(algorithm, keyPair.privateKey, data);

        cryptoOp.oncomplete = function (e) {

            var signatureBytes = getArrayResult(e.target.result);

            var opVerify = subtle.verify(algorithm, keyPair.publicKey, signatureBytes, data);

            opVerify.oncomplete = function (e) {

                var result = e.target.result;

                start();

                ok(result, "s = " + bytesToHexString(signatureBytes));
            }

            opVerify.onerror = ecdsaError("Verify error");

        }

        cryptoOp.onerror = ecdsaError("Sign error");
    }

    keyGenOp.onerror = ecdsaError("Generate key error");

});

// These tests use the internal APIs, so they won't be available without using
// msrCrypto.test.js
if (msrCrypto.testInterface) {

    test("Test Vectors P-256 SHA-256", function () {

        runTestVectors("256");

    });

    test("Test Vectors P-384 SHA-384", function () {

        runTestVectors("384");

    });

    function runTestVectors(curveName) {

        var test = msrCrypto.testInterface;

        var vectors = testVectorsECDSA["P-" + curveName + " SHA-" + curveName + ""];

        expect(vectors.length * 3);

        for (var i = 0; i < vectors.length; i++) {

            var tv = vectors[i];

            var curve = test.cryptoECC["createP" + curveName]();

            var ecdsa = test.ecdsa(curve);

            var key = ecdsa.createKey(tv.X);

            key = {
                privateKey: {
                    d: test.cryptoMath.digitsToBytes(key.privateKey)
                },
                publicKey: {
                    x: test.cryptoMath.digitsToBytes(key.publicKey.x),
                    y: test.cryptoMath.digitsToBytes(key.publicKey.y),
                }
            }

            var signature = ecdsa.sign(key.privateKey, tv.hash, ecdsa.createKey(tv.K));

            var actualR = signature.slice(0, signature.length / 2);
            var actualS = signature.slice(-(signature.length / 2));

            var verified = ecdsa.verify(key.publicKey, signature, tv.hash);

            ok(verified, "signature: " + bytesToHexString(signature));
            equal(actualR.join(), tv.R.join(), "expected r " + bytesToHexString(actualR));
            equal(actualS.join(), tv.S.join(), "expected s " + bytesToHexString(actualS));

        }
    }

}
