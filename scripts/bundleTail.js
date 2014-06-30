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

var publicMethods = {
    subtle: msrcryptoSubtle,
    getRandomValues: function(array) {
        var i;
        var randomValues = msrcryptoPseudoRandom.getBytes(array.length);
        for (i = 0; i < array.length; i+=1) {
            array[i] = randomValues[i];
        }
        return array;
    },
    initPrng: function (entropyData) {
        /// <summary>Add entropy to the PRNG.</summary>
        /// <param name="entropyData" type="Array">Entropy input to seed or reseed the PRNG.</param>

        var entropyDataType = Object.prototype.toString.call(entropyData);

        if (entropyDataType !== "[object Array]" && entropyDataType !== "[object Uint8Array]") {
            throw new Error("entropyData must be a Array or Uint8Array");
        }

        // Mix the user-provided entropy into the entropy pool - only in the main thread.
        entropyPool && entropyPool.reseed(entropyData);

        // Reseed the PRNG that was initialized below
        msrcryptoPseudoRandom.reseed(entropyPool.read(48));
        fprngEntropyProvided = true;
    },
    stringToBase64: msrcryptoUtilities.toBase64,
    base64ToString: msrcryptoUtilities.base64ToString
};

// Expose the math library if present
if (typeof cryptoMath !== "undefined") { 
    publicMethods.cryptoMath = cryptoMath; 
}

if (typeof testInterface !== "undefined") {
    publicMethods.testInterface = testInterface;
}

// Initialize the main entropy pool instance on the main thread, only.
// I want only the main thread to create and manage the central entropy pool.
// All workers would have their own PRNG instance initialized by injected entropy from the main thread.
var entropyPool;
if (!runningInWorkerInstance) {
    entropyPool = entropyPool || new MsrcryptoEntropy();

    // Initialize the entropy pool in the main thread.
    // There is only one entropy pool.
    entropyPool.init();
    var localEntropy = entropyPool.read(48);            // 48 is from SP800-90A; could be longer
    msrcryptoPseudoRandom.init(localEntropy);
}

return publicMethods;

})();