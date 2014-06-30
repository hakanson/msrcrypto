///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\head.js
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

// #region JSHint/JSCop
/* global arrayHelper */
/* global asyncMode: true */
/* global createProperty */
/* global defined */
/* global msrcryptoUtilities */
/* global msrcryptoWorker */
/* global msrcryptoPseudoRandom */
/* global fprngEntropyProvided: true */
/* global runningInWorkerInstance */
/* global scriptUrl */
/* global setterSupport */
/* global webWorkerSupport */
/* global operations */
/* jshint -W098 */
/* W098 is 'defined but not used'. We have not-yet-implemented apis stubbed out. */

/// <reference path="jsCopDefs.js" />
/// <reference path="global.js" />
/// <reference path="worker.js" />
/// <reference path="utilities.js" />

/// These are terms that JSCop thinks are misspelled, so we have to add them to its dictionary
/// <dictionary>
///    concat, msrcrypto, onabort, oncomplete, onerror, onmessage, onprogress, Params, prng,
///    syncWorker, webworker, webworkers, obj
/// </dictionary>

//  JSCop cannot figure out the types correctly
/// <disable>JS3092.DeclarePropertiesBeforeUse</disable>

// #endregion JSHint/JSCop

var msrcryptoSubtle;

// This code is not used in web worker instance.
if (!runningInWorkerInstance) {

    msrcryptoSubtle = (function() {
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\syncWorker.js
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

// This worker is used when webworkers aren't available.
// It will function synchronously but use the same
//   mechanisms that the asynchronous webworkers use.
function syncWorker() {
    var result;

    // PostMessage is how you interact with a worker. You post some data to the worker
    // and it will process it and return it's data to the onmessage function.
    // Since we're really running synchronously, we call the crypto function in
    // PostMessage and wait for the result. Then we call the OnMessage fuction with
    // that result. This will give the same behavior as a web-worker.
    function postMessage(data) {

        // Web-workers will automatically return an error message when an 
        // error is thrown within the web worker.
        // When using a sync worker, we'll have to catch thrown errors, so we
        // need a try/catch block here.
        try {
            result = msrcryptoWorker.jsCryptoRunner(/*@static_cast(typeEvent)*/{ data: data });

            // 'process' operations don't return values, so we don't
            // forward the worker return message.
            if (!data.operationSubType || data.operationSubType !== "process") {
                this.onmessage({ data: result });
            }

        } catch (ex) {
            this.onerror({ data: ex.description, type: "error" });
        }
    }

    return {
        postMessage: postMessage,
        onmessage: null,
        onerror: null,
        terminate: function () {
            // This is a no-op to be compatible with webworker.
        }
    };
}
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\operations.js
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

/// <dictionary>Obj,oncomplete,onerror</dictionary>

var ie8OnCompletePollingInterval = 100; // Milliseconds

function baseOperation(processResults) {

    var result = null,
        oncompleteCallback = null,
        onerrorCallback = null,
        retObj;

    function opAddEventListener(eventType, listener) {

    }

    function opRemoveEventListener(eventType, listener) {

    }

    function onCompleteSet(value) {
        oncompleteCallback = value;

        // If we are just now setting the oncomplete event, but we already have a result,
        //   call the oncomplete function passing the result.
        // This can happen if the crypto function finishes before the oncompleted handler has been set.
        if (this.result) {
            oncompleteCallback({ target: this });
        }
    }

    function onErrorSet(value) {
        onerrorCallback = value;
    }

    function onCompleteGet() {
        return oncompleteCallback;
    }

    function onErrorGet() {
        return onerrorCallback;
    }

    function opDispatchEvent(/*@type(Event)*/e) {

        // If the event is an Error call the onError callback
        if (e.type === "error") {

            // If the onerror callback has been set, call it.
            if (this.onerror) {
                this.onerror(e);
            }
            return;
        }

        // If we've returned from a 'process' call, do nothing.
        if (e.type === "process") {
            return;
        }

        // Otherwise call the oncomplete callback
        this.result = processResults(e.data);

        // If the oncomplete callback has been set, call it.
        if (this.oncomplete) {
            this.oncomplete({ target: this });

        } else {  // The oncomplete event has not been set

        }

        return;
    }

    retObj = {
        dispatchEvent: opDispatchEvent,
        addEventListener: opAddEventListener,
        removeEventListener: opRemoveEventListener,
        result: null
    };

    createProperty(retObj, "oncomplete", null, onCompleteGet, onCompleteSet);
    createProperty(retObj, "onerror", null, onErrorGet, onErrorSet);

    return retObj;
}

function keyOperation() {

    function processResult(result) {

        // Could be the result of an import, export, generate.
        // Get the keyData and keyHandle out.
        switch (result.type) {

            // KeyImport: save the new key
            case "keyGeneration":
            case "keyImport":
            case "keyDerive":
                keys.add(result.keyHandle, result.keyData);
                return result.keyHandle;

            // KeyExport: return the export data
            case "keyExport":
                return toArrayBufferIfSupported(result.keyHandle);

            case "keyPairGeneration":
                keys.add(result.keyPair.publicKey.keyHandle, result.keyPair.publicKey.keyData);
                keys.add(result.keyPair.privateKey.keyHandle, result.keyPair.privateKey.keyData);
                return {
                    publicKey: result.keyPair.publicKey.keyHandle,
                    privateKey: result.keyPair.privateKey.keyHandle,
                };

            default:
                throw new Error("Unknown key operation");
        }

        return;
    }

    return baseOperation(processResult);
}

function cryptoOperation(cryptoContext) {

    function processResult(result) {

        // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
        result = toArrayBufferIfSupported(result);

        // A normal array will be returned.
        return result;
    }

    var op = baseOperation(processResult);

    op.process = function (buffer) {
        cryptoContext.operationSubType = "process";
        cryptoContext.buffer = utils.toArray(buffer);
        workerManager.continueJob(this,
            utils.clone(cryptoContext));
    };

    op.finish = function () {
        cryptoContext.operationSubType = "finish";
        cryptoContext.buffer = [];
        workerManager.continueJob(this,
            utils.clone(cryptoContext));
    };

    op.abort = function () {
        workerManager.abortJob(this);
    };

    op.onabort = null;
    op.onprogress = null;

    op.algorithm = cryptoContext.algorithm || null;
    op.key = cryptoContext.keyHandle || null;

    return op;
}

function toArrayBufferIfSupported(dataArray) {

    // If the browser supports typed-arrays, return an ArrayBuffer like IE11.
    if (typedArraySupport && dataArray.pop) {

        // We can't write to an ArrayBuffer directly so we create a Uint8Array
        //   and return it's buffer property.
        return (new Uint8Array(dataArray)).buffer;
    }

    // Do nothing and just return the passed-in array.
    return dataArray;
}

// IE8 doesn't support setters/getters on non-dom objects
//   so we have to poll the oncomplete property to see if it's been
//   set, then call it when running in synchronous mode.
function ie8NoSetterFix( /*@type(baseOperation)*/operation) {

    if (operation.oncomplete) {
        operation.oncomplete({ target: operation });
    } else {
        setTimeout(
            function () {
                ie8NoSetterFix(operation);
            }, ie8OnCompletePollingInterval);
    }
}
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\keyManager.js
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

// Storage for the keyData.
// Stored as {keyHandle: keyHandle, keyData: keyData} objects.
var keys = [];
keys.add = function (keyHandle, keyData) {
    keys.push({ keyHandle: keyHandle, keyData: keyData });
};
keys.remove = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            keys = keys.splice(i, 1);
            return;
        }
    }
};
keys.lookup = function (keyHandle) {
    for (var i = 0; i < keys.length; i++) {
        if (keys[i].keyHandle === keyHandle) {
            return keys[i].keyData;
        }
    }
    return null;
};
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\workerManager.js
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

// Manages the pool of webworkers and job queue.
// We first try to find an idle webworker and pass it a crypto job.
// If there are no workers or they are all busy, we'll create a new one.
// If we're at our (somewhat arbitrary) limit for workers we'll queue the 
//   job until a worker is free.
// When a worker finishes and the queue is empty it will kill itself to
//   free resources.
// However, we will keep a couple idle workers alive for future use.
// In the case webworkers are not supported <IE10 we will run in synchronous
//   mode. Jobs will be executed synchronously as they arrive using a single
//   syncWorker (pretend webworker that just runs synchronously in this same script).
var workerManager = (function () {

    // The max number of webworkers we'll spawn.
    var maxWorkers = 15;

    // The number of idle webworkers we'll allow to live for future use.
    var maxFreeWorkers = 4;

    // Storage for webworker.
    var workerPool = [];

    // Queue for jobs when all workers are busy.
    var jobQueue = [];

    // Each job gets and id.
    var jobId = 0;

    function getFreeWorker() {

        purgeWorkerType(!asyncMode);

        // Get the first non-busy worker
        for (var i = 0; i < workerPool.length; i++) {
            if (!workerPool[i].busy) {
                return workerPool[i];
            }
        }

        return null;
    }

    function purgeWorkerType(webWorker) {
        for (var i = workerPool.length - 1; i >= 0; i -= 1) {
            if (workerPool[i].isWebWorker === webWorker) {
                workerPool[i].terminate();
                workerPool.splice(i, 1);
            }
        }
    }

    function freeWorkerCount() {
        var freeWorkers = 0;
        for (var i = 0; i < workerPool.length; i++) {
            if (!workerPool[i].busy) {
                freeWorkers += 1;
            }
        }
        return freeWorkers;
    }

    function addWorkerToPool(worker) {
        workerPool.push(worker);
    }

    function removeWorkerFromPool(worker) {
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i] === worker) {
                // Kill the webworker.
                worker.terminate();
                // Remove the worker object from the pool.
                workerPool.splice(i, 1);
                return;
            }
        }
    }

    function lookupWorkerByOperation(operation) {
        // Find this worker in the array.
        for (var i = 0; i < workerPool.length; i++) {
            if (workerPool[i].operation === operation) {
                return workerPool[i];
            }
        }
        // Didn't find the worker!?
        return null;
    }

    function queueJob(operation, data) {
        jobQueue.push({ operation: operation, data: data, id: jobId++ });
    }

    function jobCompleted(worker) {

        worker.busy = false;
        worker.operation = null;

        // Check the queue for waiting jobs if in async mode
        if (asyncMode) {
            if (jobQueue.length > 0) {
                var job = jobQueue.shift();
                continueJob(job.operation, job.data);

            } else if (freeWorkerCount() > maxFreeWorkers) {
                removeWorkerFromPool(worker);
            }
        }

    }

    function createNewWorker(operation) {

        // Use a web worker if supported
        //   else use a synchronous worker.
        var worker;

        if (asyncMode) {
            try {
                worker = new Worker(scriptUrl);
                worker.postMessage({ prngSeed: msrcryptoPseudoRandom.getBytes(48) });
                worker.isWebWorker = true;
            } catch (ex) {
                asyncMode = false;
                publicMethods.forceSync = true;
                worker = syncWorker();
                worker.isWebWorker = false;
            }

        } else {
            worker = syncWorker();
            worker.isWebWorker = false;
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        worker.busy = false;

        // The worker will call this function when it completes its job.
        worker.onmessage = function (/*@type(typeEvent)*/ e) {

            var op = worker.operation;

            // Check if there are queued jobs for this operation
            for (var i = 0; i < jobQueue.length; i++) {
                if (jobQueue[i].operation === worker.operation) {
                    var job = jobQueue[i];
                    jobQueue.splice(i, 1);
                    postMessageToWorker(worker, job.data);
                    return;
                }
            }

            // Send the results to the operation object and it will fire
            //   it's onCompleted event.
            if (op && e.data.type !== "process") {
                jobCompleted(worker);
                op.dispatchEvent(e);
            }
        };

        // If an error occurs within the worker.
        worker.onerror = function (/*@type(typeEvent)*/ e) {

            var op = worker.operation;

            jobCompleted(worker);

            // Send the error to the operation object and it will fire
            //   it's onError event.
            op.dispatchEvent(e);

        };

        // Add this new worker to the worker pool.
        addWorkerToPool(worker);

        return worker;
    }

    function abortJob(cryptoOperationObject) {
        var worker = lookupWorkerByOperation(cryptoOperationObject);
        if (worker) {
            removeWorkerFromPool(worker);
        }
    }

    // Creates or reuses a worker and starts it up on work.
    function runJob(/*@dynamic*/ operation, data) {

        var worker = null;

        // If the caller adds the "forceSync" property and sets it to true.
        // Then run in synchronous mode even if webworkers are available.
        // This can be turned on or off on the fly.
        asyncMode = webWorkerSupport && !(publicMethods.forceSync);


        // Get the first idle worker.
        worker = getFreeWorker();

        // Queue this job if all workers are busy and we're at our max instances
        if (asyncMode && worker === null && workerPool.length >= maxWorkers) {
            queueJob(operation, data);
            return;
        }

        // No idle workers, we'll have to create a new one.
        if (worker === null) {
            worker = createNewWorker(operation);
        }

        if (worker === null) {
            queueJob(operation, data);
            throw new Error("could not create new worker");
        }

        // Store the operation object as a property on the worker
        //   so we can know which operation this worker is working for.
        worker.operation = operation;

        // Mark this worker as 'busy'. It's about to run a job.
        worker.busy = true;

        // Start the worker
        postMessageToWorker(worker, data);

    }

    function continueJob(/*type(cryptoOperation)*/operation, data) {

        // Lookup the worker that is handling this operation
        var worker = lookupWorkerByOperation(operation);

        if (worker) {
            postMessageToWorker(worker, data);
            return;
        }

        // If we didn't find a worker, this is probably the first
        //  'process' message so we need to start a new worker.
        runJob(operation, data);

    }

    function postMessageToWorker(worker, data) {
        // Start the worker now if using webWorkers
        //   else, defer running until later.
        if (asyncMode) {
            worker.data = data;
            worker.postMessage(data);
        } else {
            setTimeout(function () { worker.postMessage(data); }, 0);
        }

    }

    return {
        runJob: runJob,
        continueJob: continueJob,
        abortJob: abortJob
    };

})();
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\subtle.js
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

var utils = msrcryptoUtilities;

function checkOperation(operationType, algorithmName) {
    if (!operations.exists(operationType, algorithmName)) {
        throw new Error("unsupported algorithm");
    }
}

// The list of possible parameters passed to the subtle interface.
var subtleParameters = [
   /* 0 */ { name: "algorithm", type: "Object", required: true },
   /* 1 */ { name: "keyHandle", type: "Object", required: true },
   /* 2 */ { name: "buffer", type: "Array", required: false },
   /* 3 */ { name: "signature", type: "Array", required: true },
   /* 4 */ { name: "format", type: "String", required: true },
   /* 5 */ { name: "keyData", type: "Array", required: true },
   /* 6 */ { name: "extractable", type: "Boolean", required: false },
   /* 7 */ { name: "keyUsages", type: "Array", required: false },
   /* 8 */ { name: "derivedKeyType", type: "Object", required: true },
   /* 9 */ { name: "length", type: "Number", required: false }
];

// The set of expected parameters passed to each subtle function.
var subtleParametersSets = {
    encrypt: [0, 1, 2],
    decrypt: [0, 1, 2],
    sign: [0, 1, 2],
    verify: [0, 1, 3, 2],
    digest: [0, 2],
    generateKey: [0, 6, 7],
    importKey: [4, 5, 0, 6, 7],
    exportKey: [0, 4, 1, 6, 7],
    deriveKey: [0, 1, 8, 6, 7],
    deriveBits: [0, 1, 9]
};

// Looks up the stored key data for a given keyHandle
function lookupKeyData(handle) {
    var data = keys.lookup(handle);

    if (!data) {
        throw new Error("key not found");
    }

    return data;
}

// This function processes each parameter passed by the user. Each parameter
// is compared against an expected parameter. It should be of the expected type.
// Typed-Array parameters are converted to regular Arrays.
function buildParameterCollection(operationName, parameterSet) {

    var parameterCollection = { operationType: operationName },
        operationParameterSet = subtleParametersSets[operationName];

    for (var i = 0; i < operationParameterSet.length; i += 1) {

        var expectedParam = subtleParameters[operationParameterSet[i]];
        var actualParam = parameterSet[i];

        // Verify the required parameters are present.
        if (!actualParam) {
            if (expectedParam.required) {
                throw new Error(expectedParam.name);
            } else {
                continue;
            }
        }

        // If this parameter is a typed-array convert it to a regular array.
        if (actualParam.subarray) {
            actualParam = utils.toArray(actualParam);
        }

        // Verify the actual parameter is of the expected type.
        if (type(actualParam) !== expectedParam.type) {
            throw new Error(expectedParam.name);
        }

        // If this parameter an algorithm object convert it's name to lowercase.
        if (expectedParam.name === "algorithm") {

            actualParam.name = actualParam.name.toLowerCase();

            // If the algorithm has a typed-array IV, convert it to a regular array.
            if (actualParam.iv) {
                actualParam.iv = utils.toArray(actualParam.iv);
            }

            // If the algorithm has a typed-array AdditionalData, convert it to a regular array.
            if (actualParam.additionalData) {
                actualParam.additionalData = utils.toArray(actualParam.additionalData);
            }
        }

        parameterCollection[expectedParam.name] = actualParam;
    }

    return parameterCollection;
}

function executeOperation(operationName, parameterSet, keyFunc) {

    var pc = buildParameterCollection(operationName, parameterSet);

    checkOperation(operationName, pc.algorithm.name);

    // Add the key data to the parameter object
    if (pc.keyHandle) {
        pc.keyData = lookupKeyData(pc.keyHandle);
    }

    // ECDH.DeriveBits passes a public key in the algorithm
    if (pc.algorithm && pc.algorithm.publicKey) {
        pc.additionalKeyData = lookupKeyData(pc.algorithm.publicKey);
    }

    var op = keyFunc ? keyOperation(pc) : cryptoOperation(pc);

    // Run the crypto now if a buffer is supplied
    //   else wait until process and finish are called.
    if (keyFunc || pc.buffer || operationName === "deriveBits") {
        workerManager.runJob(op, pc);
    }

    return op;
}

var publicMethods = {

    encrypt: function (/*@type(Algorithm)*/ algorithm,/*@type(typeKeyHandle)*/ keyHandle, buffer) {
        return executeOperation("encrypt", arguments, 0);
    },

    decrypt: function (/*@type(Algorithm)*/ algorithm, /*@type(typeKeyHandle)*/ keyHandle, buffer) {
        return executeOperation("decrypt", arguments, 0);
    },

    sign: function (/*@type(Algorithm)*/ algorithm, /*@type(typeKeyHandle)*/ keyHandle, buffer) {
        return executeOperation("sign", arguments, 0);
    },

    verify: function (/*@type(Algorithm)*/ algorithm, /*@type(typeKeyHandle)*/ keyHandle, signature, buffer) {
        return executeOperation("verify", arguments, 0);
    },

    digest: function (/*@type(Algorithm)*/ algorithm, buffer) {
        return executeOperation("digest", arguments, 0);
    },

    generateKey: function (/*@type(Algorithm)*/ algorithm, extractable, keyUsages) {
        return executeOperation("generateKey", arguments, 1);
    },

    deriveKey: function (/*@type(Algorithm)*/ algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
        return executeOperation("deriveKey", arguments, 1);
    },

    deriveBits: function (/*@type(Algorithm)*/ algorithm, baseKey, length) {
        return executeOperation("deriveBits", arguments, 0);
    },

    importKey: function (format, keyData, algorithm, extractable, keyUsage) {
        return executeOperation("importKey", arguments, 1);
    },

    exportKey: function (format, /*@type(typeKeyHandle)*/ keyHandle) {
        // Export is one of the few calls where the caller does not supply an algorithm 
        // since it's already part of the key to be exported.
        // So, we're pulling out of the key and adding it to the parameter set since
        // it's used as a switch to route the parameters to the right function.
        // Now we don't have to treat this as a special case in the underlying code.
        return executeOperation("exportKey", [keyHandle.algorithm, format, keyHandle], 1);
    },

    wrapKey: function (keyHandle, keyEncryptionKey, keyWrappingAlgorithm) {
        throw new Error("not implemented");
    },

    unwrapKey: function (wrappedKey, keyAlgorithm, keyEncryptionKey, extractable, keyUsage) {
        throw new Error("not implemented");
    }

};
///#source 1 1 C:\SD\Enigma\incubations\msrcrypto\msrCrypto\scripts\subtle\tail.js
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

return publicMethods;

})();

}
