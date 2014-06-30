﻿//*********************************************************
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

/* global msrcryptoUtilities */
/* global arrayHelper */
/* global MsrcryptoPrng */

/* jshint -W016 */

/// <reference path="random.js" />
/// <reference path="utilities.js" />
/// <reference path="arrayHelper.js" />
/// <reference path="jsCopDefs.js" />

/// <dictionary>arr,msrcrypto,Prng,req,res,mozilla,polyfill,PRNGs,redirectlocale,redirectslug</dictionary>

/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

/// #endregion JSCop/JsHint

function MsrcryptoEntropy() {
    /// <summary>Opportunistic entropy collector.</summary>
    /// <remarks>See E.Stark, M.Hamburg, D.Boneh, "Symmetric Cryptography in Javascript", ACSAC, 2009.
    /// This is not an object instantiation, but the definition of the object. The actual
    /// object must be instantiated somewhere else as needed.
    /// If window.{crypto,msCrypto}.getRandomValues() function is present, do not register mouse and JS load events,
    /// because they slow down the execution, and it is not clear how much they contributed over and above
    /// a cryptographic random value.
    /// </remarks>

    var poolLength = 48;      // In bytes, from SP800-90A, Section 10.2.1. See random.js for constraints.
    var collectorPool = [];
    var collectorPoolLength = 128;  // Bytes to collect before stopping; collectors are restartable.
    var collectorsRegistered = 0;
    var entropyPoolPrng = new MsrcryptoPrng();
    var initialized = false;
    var cryptographicPRNGPresent = false;
    var headerList = ["Cookie", "RedirectUri", "ETag", "x-ms-client-antiforgery-id", "x-ms-client-request-id", "x-ms-client-session-id", "SubscriptionPool"];

    function collectEntropy() {
        /// <summary>Initialize the internal pool with as much randomness as one can get in JS.
        /// In the worst case, there is zero bits of entropy.</summary>

        var i, pool = [];

        // In Safari, as of r39510, reportedly, Math.random() is cryptographically secure on Mac and Windows.
        // Even if it isn't, mix that in via XORing into the existing array.
        // According to ECMA, Math.random() returns [0,1). Thus, multiply it by 256 to get [0,256).
        for (i = 0; i < poolLength; i += 1) {
            pool[i] = Math.floor(Math.random() * 256);
        }

        // For browsers that implement window.crypto.getRandomValues, use it.
        var prngCrypto = window.crypto || window.msCrypto;       // WARNING: !!! Do not put this in a function (remember polyfill) !!!
        if (prngCrypto && typeof prngCrypto.getRandomValues === "function") {
            if (window.Uint8Array) {
                var res = new window.Uint8Array(poolLength);
                prngCrypto.getRandomValues(res);
                pool = pool.concat(Array.apply(null, /*@static_cast(Array)*/res));
                cryptographicPRNGPresent = true;
            }
        }

        // Read HTTP headers that contain entropy and reseed the entropy pool
        var req = new XMLHttpRequest();
        for (i = 0; i < headerList.length; i += 1) {
            try {
                var header = req.getResponseHeader(headerList[i]);
                if (header) {
                    var arr = msrcryptoUtilities.stringToBytes(header);
                    pool = pool.concat(arr);
                }
            }
            catch (err) {
                // Ignore any header I can't get
            }
        }

        if (!cryptographicPRNGPresent) {
            // Add any data in the collector pool, empty the collector pool, and restart collectors.
            pool = pool.concat(collectorPool.splice(0, collectorPool.length));
            collectors.startCollectors();
        }

        // Worst case: initialized with Math.random()
        initialized ? entropyPoolPrng.reseed(pool) : entropyPoolPrng.init(pool);
        initialized = true;
    }

    function updatePool(entropyData) {
        /// <summary>Collect the incoming data into the pool, and
        /// empty the pool into the entropy PRNG state when the pool is full.
        /// This function is additive entropy, only; this is not the main source of entropy.</summary>
        /// <param name="entropyData" type="Array">Entropy input.</param>
        for (var i = 0; i < entropyData.length; ++i) {
            collectorPool.push(entropyData[i]);
        }
        if (collectorPool.length >= collectorPoolLength) {
            // Stop the collectors (performance reasons).
            // The real entropy does not come from the event callbacks: these are at best uniquifiers.
            collectors.stopCollectors();
        }
    }

    // Event listeners are not supported in IE 8.
    // See https://developer.mozilla.org/en-US/docs/Web/API/EventTarget.addEventListener?redirectlocale=en-US&redirectslug=DOM%2FEventTarget.addEventListener
    // to add IE8 support.
    // BUGBUG: For the time being, I am not bothering with IE8 support - fix this.
    var collectors = (function () {
        return {
            startCollectors: function () {
                if (!this.collectorsRegistered) {
                    if (window.addEventListener) {
                        window.addEventListener("mousemove", this.MouseEventCallBack, true);
                        window.addEventListener("load", this.LoadTimeCallBack, true);
                    } else if (document.attachEvent) {
                        document.attachEvent("onmousemove", this.MouseEventCallBack);
                        document.attachEvent("onload", this.LoadTimeCallBack);
                    } else {
                        throw new Error("Can't attach events for entropy collection");
                    }

                    this.collectorsRegistered = 1;
                }
            },
            stopCollectors: function () {
                if (this.collectorsRegistered) {
                    if (window.removeEventListener) {
                        window.removeEventListener("mousemove", this.MouseEventCallBack, 1);
                        window.removeEventListener("load", this.LoadTimeCallBack, 1);
                    } else if (window.detachEvent) {
                        window.detachEvent("onmousemove", this.MouseEventCallBack);
                        window.detachEvent("onload", this.LoadTimeCallBack);
                    }

                    this.collectorsRegistered = 0;
                }
            },
            MouseEventCallBack: function (eventData) {
                /// <summary>Add the mouse coordinates to the entropy pool and the Date.</summary>
                /// <param name="eventData">Event data with mouse information.</param>
                var d = (new Date()).valueOf();
                var x = eventData.x || eventData.clientX || eventData.offsetX || 0;
                var y = eventData.y || eventData.clientY || eventData.offsetY || 0;
                var arr = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff,
                        x & 0x0ff, (x >> 8) & 0x0ff, y & 0x0ff, (y >> 8) & 0x0ff];

                updatePool(arr);
            },
            LoadTimeCallBack: function () {
                /// <summary>Add date to the entropy pool.</summary>
                /// <remarks>Date valueOf() returns milliseconds since midnight 1/1/1970 UTC in a 32 bit integer</remarks>
                var d = (new Date()).valueOf();
                var dateArray = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff];

                updatePool(dateArray);
            }
        };
    })();

    return {
        init: function () {
            collectEntropy();

            // Register collectors
            if (!cryptographicPRNGPresent && !collectorsRegistered) {
                try {
                    collectors.startCollectors();
                }
                catch (e) {
                    // Ignore errors instead of trying to do something browser specific. That is not tractable.
                    // It is expected that the calling program injects most of the entropy or the build-in collectors
                    // contributes rather than registered events.
                }
            }
        },

        reseed: function (entropy) {
            /// <summary>Mix in entropy into the pool.</summary>
            /// <param name="entropy" type="Array">Entropy to mix in.</param>
            entropyPoolPrng.reseed(entropy);
        },

        read: function (length) {
            /// <summary>Read entropy from the entropy pool. This function fails if there isn't enough entropy.</summary>
            /// <param name="length" type="Number">Number of bytes of requested entropy.</param>
            /// <returns type="Array">Entropy if there is enough in the pool, or undefined if there isn't enough entropy.</returns>
            if (!initialized) {
                throw new Error("Entropy pool is not initialized.");
            }

            var ret = entropyPoolPrng.getBytes(length);

            // TODO: Do this async?
            //       No, another call may come through before the pool is reseeded.
            //       All PRNGs have their own running state anyhow. They can reseed themselves in async mode, if need be.
            collectEntropy();

            return ret;
        }
    };
}