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
/* global msrcryptoUtilities */
/* jshint -W016 */
/* jshint -W052 */

/// <reference path="operations.js" />
/// <reference path="utilities.js" />

/// <dictionary>msrcrypto, der, sha, uint, int, maj</dictionary>

/// #endregion JSCop/JsHint

var msrcryptoSha512 = (function () {

    function add(x0, x1, y0, y1, resultArray) {

        // The sum here may result in a number larger than 32-bits.
        // Or-ing with zero forces to a 32-bit signed internal state
        // and a truncation to a 32-bit number;
        var lowSum = (x1 + y1) | 0;

        // If lowSum is less than either parameter (x1 or y1), we know we overflowed
        //   and a carry will need to be added to the high order bits.
        // The 32-bit integer is signed. So large numbers can flip to negative values.
        // The zero-shift pulls the number back out of the 32-bit state so we know
        //   we're comparing positive values.
        var carry = (lowSum >>> 0 < y1 >>> 0);

        resultArray[0] = (x0 + y0 + carry) | 0;
        resultArray[1] = lowSum;

        return;
    }

    var hashFunction = function (hashName, der, h, k, truncateTo) {

        var blockBytes = 128,
         hv = [],
         w = [],
         buffer = [],
         blocksProcessed = 0;

        initializeHashValues();

        // Hashing using 64 bit registers. 2-32bit values as high and low
        function hashBlocks( /*@type(Array)*/ message) {

            var blockCount = Math.floor(message.length / blockBytes),
                t, i,
                tah, tal, tbh, tbl, xh, xl,
                tc = [],
                td = [],
                te = [],
                block, index;

            for (block = 0; block < blockCount; block++) {

                for (t = 0; t < 32; t++) {
                    index = block * blockBytes + t * 4;
                    w[t] = message.slice(index, index + 4);
                    w[t] = (w[t][0] << 24) | (w[t][1] << 16) | (w[t][2] << 8) | w[t][3];
                }

                // 16 ≤ t ≤ 80
                for (t = 32; t < 160; t += 2) {

                    xh = w[t - 30];
                    xl = w[t - 29];

                    tah = (xh >>> 1 | xl << 31) ^ (xh >>> 8 | xl << 24) ^ (xh >>> 7);
                    tal = (xl >>> 1 | xh << 31) ^ (xl >>> 8 | xh << 24) ^ (xl >>> 7 | xh << 25);

                    xh = w[t - 4];
                    xl = w[t - 3];

                    tbh = (xh >>> 19 | xl << 13) ^ (xl >>> 29 | xh << 3) ^ (xh >>> 6);
                    tbl = (xl >>> 19 | xh << 13) ^ (xh >>> 29 | xl << 3) ^ (xl >>> 6 | xh << 26);

                    add(tbh, tbl, w[t - 14], w[t - 13], tc);

                    add(tah, tal, tc[0], tc[1], tc);

                    add(w[t - 32], w[t - 31], tc[0], tc[1], tc);

                    w[t] = tc[0]; w[t + 1] = tc[1];
                }

                var ah = hv[0], al = hv[1],
                    bh = hv[2], bl = hv[3],
                    ch = hv[4], cl = hv[5],
                    dh = hv[6], dl = hv[7],
                    eh = hv[8], el = hv[9],
                    fh = hv[10], fl = hv[11],
                    gh = hv[12], gl = hv[13],
                    hh = hv[14], hl = hv[15];

                for (i = 0; i < 160; i += 2) {

                    // S1 =======================================================================
                    tah = (eh >>> 14 | el << 18) ^ (eh >>> 18 | el << 14) ^ (el >>> 9 | eh << 23);
                    tal = (el >>> 14 | eh << 18) ^ (el >>> 18 | eh << 14) ^ (eh >>> 9 | el << 23);

                    // Ch
                    tbh = (eh & fh) ^ (gh & ~eh);
                    tbl = (el & fl) ^ (gl & ~el);

                    // C = h + S1
                    add(hh, hl, tah, tal, tc);

                    // D = ch + kConstants-i
                    add(tbh, tbl, k[i], k[i + 1], td);

                    // E = w[i] + C
                    add(tc[0], tc[1], w[i], w[i + 1], te);

                    // E = E + D  TEMP
                    add(td[0], td[1], te[0], te[1], te);

                    // D = C + E
                    add(te[0], te[1], dh, dl, tc);
                    dh = tc[0]; dl = tc[1];

                    // S0
                    tal = (al >>> 28 | ah << 4) ^ (ah >>> 2 | al << 30) ^ (ah >>> 7 | al << 25);
                    tah = (ah >>> 28 | al << 4) ^ (al >>> 2 | ah << 30) ^ (al >>> 7 | ah << 25);

                    tbl = (al & (bl ^ cl)) ^ (bl & cl);
                    tbh = (ah & (bh ^ ch)) ^ (bh & ch);

                    // S0 + maj
                    add(te[0], te[1], tah, tal, tc);
                    tah = tc[0]; tal = tc[1];

                    // 'temp' = temp + (S0 + maj)
                    add(tbh, tbl, tah, tal, tc);
                    tah = tc[0]; tal = tc[1];

                    hh = gh;
                    hl = gl; // 'h' = g
                    gh = fh;
                    gl = fl; // 'g' = f
                    fh = eh;
                    fl = el; // 'f' = e
                    eh = dh;
                    el = dl; // 'e' = d
                    dh = ch;
                    dl = cl; // 'd' = c
                    ch = bh;
                    cl = bl; // 'c' = b
                    bh = ah;
                    bl = al; // 'b' = a
                    ah = tah;
                    al = tal; // 'a' = temp
                }

                // This is how you would add without calling add()
                // hv[1] = ((hv[1] + al) | 0) >>> 0;
                // hv[0] = hv[0] + ah + (hv[1] < al >>> 0) | 0;

                add(hv[0], hv[1], ah, al, tc);
                hv[0] = tc[0]; hv[1] = tc[1];

                add(hv[2], hv[3], bh, bl, tc);
                hv[2] = tc[0]; hv[3] = tc[1];

                add(hv[4], hv[5], ch, cl, tc);
                hv[4] = tc[0]; hv[5] = tc[1];

                add(hv[6], hv[7], dh, dl, tc);
                hv[6] = tc[0]; hv[7] = tc[1];

                add(hv[8], hv[9], eh, el, tc);
                hv[8] = tc[0]; hv[9] = tc[1];

                add(hv[10], hv[11], fh, fl, tc);
                hv[10] = tc[0]; hv[11] = tc[1];

                add(hv[12], hv[13], gh, gl, tc);
                hv[12] = tc[0]; hv[13] = tc[1];

                add(hv[14], hv[15], hh, hl, tc);
                hv[14] = tc[0]; hv[15] = tc[1];
            }

            // Keep track of the number of blocks processed.
            // We have to put the total message size into the padding.
            blocksProcessed += blockCount;

            // Return the unprocessed data.
            return message.slice(blockCount * blockBytes);
        }

        function hashToBytes() {

            // Move the results to an uint8 array
            var hash = [];

            for (var i = 0; i < 16; i++) {
                hash = hash.concat([hv[i] >>> 24, (hv[i] >>> 16) & 255, (hv[i] >>> 8) & 255, hv[i] & 255]);
            }

            return hash.slice(0, truncateTo / 8);
        }

        function padBlock(/*@type(Array)*/message) {

            var padLen = blockBytes - message.length;

            // If there is 16 or less bytes of padding, pad an additional block.
            if (padLen <= 16) {
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

            // Set the message length in the last 4 bytes (32-bits worth)
            // JavaScript arrays have a max size of 32-bits.
            paddedMessage.push(messageLenBits >>> 24 & 255);
            paddedMessage.push(messageLenBits >>> 16 & 255);
            paddedMessage.push(messageLenBits >>> 8 & 255);
            paddedMessage.push(messageLenBits & 255);

            return paddedMessage;
        }

        function bufferToArray(/*@type(Array)*/dataBuffer) {

            if (dataBuffer.slice) {
                return dataBuffer;
            }

            return (dataBuffer.length === 1) ? [dataBuffer[0]] : Array.apply(null, dataBuffer);
        }

        function initializeHashValues() {
            // Set the initial hash values
            for (var l = 0; l < h.length; l++) {
                hv[l] = h[l][0] << 24 | h[l][1] << 16 | h[l][2] << 8 | h[l][3];
            }
        }

        function computeHash(messageBytes) {

            buffer = hashBlocks(bufferToArray(messageBytes));

            return finish();
        }

        function process(messageBytes) {

            // Append the new data to the buffer (previous unprocessed data)
            buffer = buffer.concat(bufferToArray(messageBytes));

            // If there is at least one block of data, hash it
            if (buffer.length >= 64) {
                // The remaining unprocessed data goes back into the buffer
                buffer = hashBlocks(buffer);
            }

            return;
        }

        function finish() {

            // All the full blocks of data have been processed. Now we pad the rest and hash
            buffer = hashBlocks(padBlock(buffer));

            // Buffer should be empty now
            if (buffer.length !== 0) {
                throw new Error("buffer.length !== 0");
            }

            var result = hashToBytes();

            // Clear the state so this instance can be reused
            buffer = [];
            initializeHashValues();
            blocksProcessed = 0;

            return result;
        }

        return {
            name: hashName,
            computeHash: computeHash,
            process: process,
            finish: finish,
            der: der,
            hashLen: truncateTo,
            maxMessageSize: 0xFFFFFFFF // (2^32 - 1 is max array size in JavaScript)
        };

    };

    var h384, h512, k512,
        der384, der512, der512_224, der512_256,
        upd = msrcryptoUtilities.unpackData;

    h384 = upd("y7udXcEFnthimikqNnzVB5FZAVowcN0XFS/s2PcOWTlnMyZn/8ALMY60SodoWBUR2wwuDWT5j6dHtUgdvvpPpA==", 4);

    h512 = upd("agnmZ/O8yQi7Z66FhMqnOzxu83L+lPgrpU/1Ol8dNvFRDlJ/reaC0ZsFaIwrPmwfH4PZq/tBvWtb4M0ZE34heQ", 4);

    k512 = upd(
        "QoovmNcoriJxN0SRI+9lzbXA+8/sTTsv6bXbpYGJ27w5VsJb80i1OFnxEfG2BdAZkj+CpK8ZT5urHF7" +
        "V2m2BGNgHqpijAwJCEoNbAUVwb74kMYW+TuSyjFUMfcPV/7Ticr5ddPJ7iW+A3rH+OxaWsZvcBqclxx" +
        "I1wZvxdM9pJpTkm2nBnvFK0u++R4Y4TyXjD8GdxouM1bUkDKHMd6ycZS3pLG9ZKwJ1SnSEqm6m5INcs" +
        "KncvUH71Hb5iNqDEVO1mD5RUu5m36uoMcZtLbQyELADJ8iY+yE/v1l/x77vDuTG4AvzPaiPwtWnkUeT" +
        "CqclBspjUeADgm8UKSlnCg5ucCe3CoVG0i/8LhshOFwmySZNLG38WsQq7VM4DROdlbPfZQpzVIuvY95" +
        "2agq7PHeyqIHCyS5H7a7mknIshRSCNTuiv+ihTPEDZKgaZku8QjABwkuLcND4l5HHbFGjBlS+MNGS6B" +
        "nW71IY1pkGJFVlqRD0DjWFV3EgKhBqoHAyu9G4GaTBFrjS0MgeN2wIUUGrUydId0zfjuuZNLC8teGbS" +
        "Kg5HAyzxclaY07YqkrjQYrLW5zKT3dj43NoLm/z1rK4o3SPgu5d77L8eKVjb0MXL2CEyHgUofCrcozH" +
        "AggaZDnskL7/+iNjHiikUGzr3oK96b75o/eyxnkVxnF48uNyUyvKJz7O6iZhnNGGuMchwMIH6tp91s3" +
        "g6x71fU9/7m7ReAbwZ6pyF2+6CmN9xaLImKYRP5gEvvkNrhtxCzUTHEcbKNt39SMEfYQyyqt7QMckkz" +
        "yevgoVyb68Qx1nxJwQDUxMxdS+yz5Ctll/KZz8ZX4qX8tvqzrW+uxsRBmMSkdYFw==", 4, 1);

    // DER encoding
    der384 = upd("MEEwDQYJYIZIAWUDBAICBQAEMA");
    der512 = upd("MFEwDQYJYIZIAWUDBAIDBQAEQA");
    der512_224 = upd("MC0wDQYJYIZIAWUDBAIFBQAEHA");
    der512_256 = upd("MDEwDQYJYIZIAWUDBAIGBQAEIA");

    return {
        sha384: hashFunction("SHA-384", der384, h384, k512, 384),
        sha512: hashFunction("SHA-512", der512, h512, k512, 512),
        sha512_224: hashFunction("SHA-512.224", der512_224, h512, k512, 224),
        sha512_256: hashFunction("SHA-512.256", der512_256, h512, k512, 256)
    };
})();

if (typeof operations !== "undefined") {

    msrcryptoSha512.hash384 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha512.sha384.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha512.sha384.finish();
        }

        return msrcryptoSha512.sha384.computeHash(p.buffer);

    };

    msrcryptoSha512.hash512 = function (/*@dynamic*/p) {

        if (p.operationSubType === "process") {
            msrcryptoSha512.sha512.process(p.buffer);
            return;
        }

        if (p.operationSubType === "finish") {
            return msrcryptoSha512.sha512.finish();
        }

        return msrcryptoSha512.sha512.computeHash(p.buffer);

    };

    operations.register("digest", "sha-384", msrcryptoSha512.hash384);
    operations.register("digest", "sha-512", msrcryptoSha512.hash512);
}

msrcryptoHashFunctions["sha-384"] = msrcryptoSha512.sha384;
msrcryptoHashFunctions["sha-512"] = msrcryptoSha512.sha512;