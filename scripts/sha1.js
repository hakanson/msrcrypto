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
/* jshint -W016 */
/* jshint -W052 */

/// <reference path="operations.js" />

/// <dictionary>msrcrypto, der, sha</dictionary>

/// <disable>JS3057.AvoidImplicitTypeCoercion</disable>

/// #endregion JSCop/JsHint

var msrcryptoSha1 = (function () {

    var hashFunction = function (name, der, h, k, truncateTo) {

        var blockBytes = 64;
        var hv = h.slice();
        var w = new Array(blockBytes);
        var buffer = [];
        var blocksProcessed = 0;

        function hashBlocks(/*@type(Array)*/message) {

            var blockCount = Math.floor(message.length / blockBytes);

            var ra, rb, rc, rd, re;
            var t, block, i, temp, x0, index;

            // Process each 64-byte block of the message
            for (block = 0; block < blockCount; block++) {

                // 0 ≤ t ≤ 15
                for (i = 0; i < 16; i++) {
                    index = block * blockBytes + i * 4;
                    // Convert 4 bytes to 32-bit integer
                    w[i] = (message[index] << 24) |
                           (message[index + 1] << 16) |
                           (message[index + 2] << 8) |
                            message[index + 3];
                }

                // 16 ≤ t ≤ 79
                for (t = 16; t < 80; t++) {
                    x0 = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
                    w[t] = (x0 << 1) | (x0 >>> 31);
                }

                ra = hv[0];
                rb = hv[1];
                rc = hv[2];
                rd = hv[3];
                re = hv[4];

                for (i = 0; i < 20; i++) {

                    // Ch(x, y, z)=(x & y) ^ (~x & z)
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += (rb & rc) ^ ((~rb) & rd);
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                for (i = 20; i < 40; i++) {

                    //Parity(x, y, z)= x ^ y ^ z
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += rb ^ rc ^ rd;
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                for (i = 40; i < 60; i++) {

                    //Maj(x, y, z)=(x & y) ^ (x & z) ^ (y & z)
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += (rb & rc) ^ (rb & rd) ^ (rc & rd);
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                for (i = 60; i < 80; i++) {

                    //Parity(x, y, z)= x ^ y ^ z
                    temp = ((ra << 5) | (ra >>> 27)) & 0xFFFFFFFF;
                    temp += rb ^ rc ^ rd;
                    temp = (temp + re + k[i] + w[i]) & 0xFFFFFFFF;

                    re = rd;
                    rd = rc;
                    rc = ((rb << 30) | (rb >>> 2)) & 0xFFFFFFFF;
                    rb = ra;
                    ra = temp;
                }

                // Need to mask 32-bits when using regular arrays
                hv[0] += ra & 0xFFFFFFFF;
                hv[1] += rb & 0xFFFFFFFF;
                hv[2] += rc & 0xFFFFFFFF;
                hv[3] += rd & 0xFFFFFFFF;
                hv[4] += re & 0xFFFFFFFF;

            }

            // Keep track of the number of blocks processed.
            // We have to put the total message size into the padding.
            blocksProcessed += blockCount;

            // Return the unprocessed data.
            return message.slice(blockCount * blockBytes);
        }

        function hashToBytes() {

            var hash = new Array(256);

            // Copy the 32-bit values to a byte array
            for (var i = 0, byteIndex = 0; i < 8; i += 1, byteIndex += 4) {
                hash[byteIndex] = hv[i] >>> 24;
                hash[byteIndex + 1] = hv[i] >>> 16 & 0xFF;
                hash[byteIndex + 2] = hv[i] >>> 8 & 0xFF;
                hash[byteIndex + 3] = hv[i] & 0xFF;
            }

            return hash.slice(0, truncateTo / 8);
        }

        // This can be optimized.
        // Currently the amount of padding is computed. Then a new array, big enough
        // to hold the message + padding is created.  The message is copied to the
        // new array and the padding is placed at the end.
        // We don't really need to create an entire new array and copy to it.
        // We can just build the last padded block and store it.
        // Then when computing the hash, substitute it for the last message block.
        function padBlock( /*@type(Array)*/ message) {

            var padLen = blockBytes - message.length;

            // If there is 8 or less bytes of padding, pad an additional block.
            if (padLen <= 8) {
                padLen += blockBytes;
            }

            // Create a new Array that will contain the message + padding
            var paddedMessage = message.slice();

            // Set the 1 bit at the end of the message data
            paddedMessage.push(128);

            // Pad the array with zero. Leave 4 bytes for the message size.
            for (var i = 1; i < padLen - 4; i++) {
                paddedMessage.push(0);
            }

            // Set the length equal to the previous data len + the new data len
            var messageLenBits = (message.length + blocksProcessed * blockBytes) * 8;

            // Set the message length in the last 4 bytes
            paddedMessage.push(messageLenBits >>> 24 & 255);
            paddedMessage.push(messageLenBits >>> 16 & 255);
            paddedMessage.push(messageLenBits >>> 8 & 255);
            paddedMessage.push(messageLenBits & 255);

            return paddedMessage;
        }

        function bufferToArray(buffer) {

            // Checking for slice method to determine if this a regular array.
            if (buffer.pop) {
                return buffer;
            }

            return (buffer.length === 1) ? [buffer[0]] : Array.apply(null, buffer);
        }

        function /*@type(Array)*/ computeHash(messageBytes) {

            // Convert the input to an Array - it could be a typed array
            buffer = hashBlocks(bufferToArray(messageBytes));

            return finish();
        }

        function process(messageBytes) {

            // Append the new data to the buffer (previous unprocessed data)
            // Convert the input to an Array - it could be a typed array
            buffer = buffer.concat(bufferToArray(messageBytes));

            // If there is at least one block of data, hash it
            if (buffer.length >= 64) {
                // The remaining unprocessed data goes back into the buffer
                buffer = hashBlocks(buffer);
            }

            return;
        }

        function finish() {

            // All the full blocks of data have been processed. Now we pad the rest and hash.
            // Buffer should be empty now.
            if (hashBlocks(padBlock(buffer)).length !== 0) {
                throw new Error("buffer.length !== 0");
            }

            var result = hashToBytes();

            // Clear the hash values so this instance can be reused
            buffer = [];
            hv = h.slice();
            blocksProcessed = 0;

            return result;
        }

        return {
            name: name,
            computeHash: computeHash,
            process: process,
            finish: finish,
            der: der,
            hashLen: truncateTo,
            maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
        };

    };

    var k, h, der, upd = msrcryptoUtilities.unpackData;

    h = upd("Z0UjAe/Nq4mYutz+EDJUdsPS4fA=", 4, 1);

    k = upd("WoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlagnmZWoJ5mVqCeZlu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroW7Z66Fu2euhbtnroY8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcjxu83I8bvNyPG7zcymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdbKYsHWymLB1spiwdY", 4, 1);

    // DER encoding
    der = upd("MCEwCQYFKw4DAhoFAAQU");

    return {
        sha1: hashFunction("SHA-1", der, h, k, 160)
    };
})();

if (typeof operations !== "undefined") {

    msrcryptoSha1.hash = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha1.Sha1.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha1.Sha1.finish();
        }

        return msrcryptoSha1.sha1.computeHash(p.buffer);

    };

    operations.register("digest", "sha-1", msrcryptoSha1.hash);

}

msrcryptoHashFunctions["sha-1"] = msrcryptoSha1.sha1;
