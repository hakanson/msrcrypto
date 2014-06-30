/// <reference path="../../msrcrypto.js" />
/// <reference path="~/scripts/qunit/qunit-1.14.0.js" />
/// <reference path="testVectors/tv_aes.js" />

module("KDF");

asyncTest("Hmac 256 -> Aes 1024", function () {

    var algorithm = {
        name: "CONCAT",
        hash: { name: "sha-256" },
        algorithmId: [1, 2, 3, 4, 5, 6],
        partyUInfo: [1, 2, 3, 4, 5, 6],
        partyVInfo: [1, 2, 3, 4, 5, 6]
    };

    var keyOpGen = msrCrypto.subtle.generateKey({ name: "hmac", hash: { name: "sha-256" }, length: 256 }, true, ["deriveKey"]);

    keyOpGen.oncomplete = function (e) {

        var aesKey = e.target.result;

        var keyOpDeriveKey =
            msrCrypto.subtle.deriveKey(algorithm, aesKey, { name: "aes-cbc", length: 1024 }, true, []);

        keyOpDeriveKey.oncomplete = function (e) {

            getKeyData(e.target.result, function (keyData) {

                start();

                equal(base64UrlToBytes(keyData.k).length, 1024, "Key length correct.");

            });
        }

        keyOpDeriveKey.onerror = kdfError("deriveKey error");
    }

    keyOpGen.onerror = kdfError("generateKey error");

});

asyncTest("Aes 256 -> Aes 1024", function () {

    var algorithm = {
        name: "CONCAT",
        hash: { name: "sha-256" },
        algorithmId: [1, 2, 3, 4, 5, 6],
        partyUInfo: [1, 2, 3, 4, 5, 6],
        partyVInfo: [1, 2, 3, 4, 5, 6]
    };

    var keyOpGen = msrCrypto.subtle.generateKey({ name: "aes-cbc", length: 256 }, true, ["deriveKey"]);

    keyOpGen.oncomplete = function (e) {

        var aesKey = e.target.result;

        var keyOpDeriveKey =
            msrCrypto.subtle.deriveKey(algorithm, aesKey, { name: "aes-cbc", length: 1024 }, true, []);

        keyOpDeriveKey.oncomplete = function (e) {

            getKeyData(e.target.result, function (keyData) {

                start();

                equal(base64UrlToBytes(keyData.k).length, 1024, "Key length correct.");

            });
        }

        keyOpDeriveKey.onerror = kdfError("deriveKey error");
    }

    keyOpGen.onerror = kdfError("generateKey error");

});



function kdfError(message) {
    return function (e) {
        start();
        ok(false, message);
    }
}

