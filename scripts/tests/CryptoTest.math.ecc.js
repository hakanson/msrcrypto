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

var eccTests = eccTests || {};

module("ECC");

eccTests.getScalarMultiplicationExpected = function (k, point, ecOperator) {

    var result, kclone, one;

    if (!point.isAffine) {
        ok(false, "given point must be in affine form");
    }

    if (!point.isInMontgomeryForm) {
        ok(false, "expected point in Montgomery form");
    }

    result = point.clone();
    ecOperator.convertToJacobianForm(result);

    kclone = k.slice();

    one = cryptoMath.intToDigits(1, kclone.length);
    cryptoMath.subtract(kclone, one, kclone);

    while (!cryptoMath.isZero(kclone)) {
        ecOperator.mixedAdd(result, point, result);
        cryptoMath.subtract(kclone, one, kclone);
    }

    // convert result to normal, affine form
    ecOperator.convertToAffineForm(result);
    ecOperator.convertToStandardForm(result);

    return result;
};

eccTests.getExpectedPrecomputationTable = function (ecOperator, point, w) {

    var pCopy, twoP, expectedPoints, newPoint, i;

    pCopy = point.clone();

    // compute 2p
    if (pCopy.z === null) {
        ecOperator.convertToJacobianForm(pCopy);
    }

    twoP = pCopy.curve.allocatePointStorage();
    ecOperator.convertToJacobianForm(twoP);
    ecOperator.double(pCopy, twoP);
    ecOperator.convertToAffineForm(twoP);

    expectedPoints = [];

    // add P in Jacobian form
    expectedPoints.push(pCopy.clone());

    // add P + 2P * n for n in 2..2^w-2 in normal affine form
    for (i = 1; i < (1 << w - 2) ; i += 1) {
        newPoint = pCopy.curve.allocatePointStorage();
        ecOperator.convertToJacobianForm(newPoint);
        ecOperator.mixedAdd(expectedPoints[i - 1], twoP, newPoint);
        expectedPoints.push(newPoint);
    }

    for (i = 0; i < expectedPoints.length; i += 1) {
        if (!expectedPoints[i].isAffine) {
            ecOperator.convertToAffineForm(expectedPoints[i]);
        }
        if (expectedPoints[i].isInMontgomeryForm) {
            ecOperator.convertToStandardForm(expectedPoints[i]);
        }
    }

    return expectedPoints;
};

test("eccTestDoubleAdd", function () {

    var curve, point1, point2, expectedValue, ecOperator;

    // USE NIST CURVE FOR TESTING
    curve = cryptoECC.createP256();

    // A random point on the curve, generated by using Magma
    point1 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10),
        null,
        false
    );

    point2 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("47613893567070068258577018714129972946576730457691498223532169399056904097106", 10),
        cryptoMath.stringToDigits("69975134274942587319816459475221188408835613494163681846165872326255291661680", 10),
        null,
        false
    );

    expectedValue = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("72346342021525370269786550478766846754647858881119647264472876203598334194498", 10),
        cryptoMath.stringToDigits("106113343889836374066327501855796791577657194411937940215620361528100539219688", 10),
        null,
        false
    );

    ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);
    ecOperator.convertToMontgomeryForm(point1);
    ecOperator.convertToJacobianForm(point1);
    ecOperator.convertToMontgomeryForm(point2);

    ecOperator.mixedDoubleAdd(point1, point2, point1);

    if (point1.isAffine === true) {
        ok(false, "point1.isAffine == true");
    }

    // for comparison with results from Magma, we convert to Affine
    ecOperator.convertToAffineForm(point1);
    ecOperator.convertToStandardForm(point1);

    if (cryptoMath.sequenceEqual(point1.x, expectedValue.x) === false) {
        ok(false, 'eccTestDoubleAdd: point1.x != expectedValue.x');
    }

    if (cryptoMath.sequenceEqual(point1.y, expectedValue.y) === false) {
        ok(false, "point1.y != expectedValue.y");
    }

    ok(true);

});

test("eccTestSimplePointDoubling", function () {

    // USE NIST CURVE FOR TESTING
    var curve = cryptoECC.createP256();

    // A random point on the curve, generated by using Magma
    var point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );

    // 2 * point, expected value
    var expectedValue = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("48966811922282644868055304540023198630821617313810671269304062775322461326085", 10),
        cryptoMath.stringToDigits("62766347176538165850925649571367125874094146714736151515015472701383455763403", 10)
        );

    // Double the point
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);
    ecOperator.convertToMontgomeryForm(point);
    ecOperator.convertToJacobianForm(point);

    ecOperator.double(point, point);

    ecOperator.convertToAffineForm(point);
    ecOperator.convertToStandardForm(point);

    if (point.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    if (cryptoMath.sequenceEqual(point.x, expectedValue.x) === false) {
        ok(false, "point.x != expectedValue.x");
    }

    if (cryptoMath.sequenceEqual(point.y, expectedValue.y) === false) {
        ok(false, "point.y != expectedValue.y");
    }

    ok(true);
});

test("eccTestBN254PointDoubling", function () {

    // USE BN254 CURVE FOR TESTING
    var curve = cryptoECC.createBN254();

    // A random point on the curve, generated by using Magma
    var point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("16265663556941183235667673432237010020467740389186255294070246486864918269252", 10),
        cryptoMath.stringToDigits("2939044720388101534411915484259893450700762028171953183140911100854998190050", 10)
        );

    // 2 * point, expected value
    var expectedValue = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("14901344033627802951703803378538431769169502232165333988408037403298805088528", 10),
        cryptoMath.stringToDigits("16009713324160370204954065578174732653405188919720570351038009899344697454249", 10)
        );

    // Double the point
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);
    ecOperator.convertToMontgomeryForm(point);
    ecOperator.convertToJacobianForm(point);

    ecOperator.double(point, point);

    ecOperator.convertToAffineForm(point);
    ecOperator.convertToStandardForm(point);

    if (point.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    if (cryptoMath.sequenceEqual(point.x, expectedValue.x) === false) {
        ok(false, "point.x != expectedValue.x");
    }

    if (cryptoMath.sequenceEqual(point.y, expectedValue.y) === false) {
        ok(false, "point.y != expectedValue.y");
    }

    ok(true);
});

test("eccTestInfinityPointDoubling", function () {

    // USE NIST CURVE FOR TESTING
    var curve = cryptoECC.createP256();

    // A point at infinity on the curve
    var point = curve.allocatePointStorage();
    point.isInfinity = true;

    // Double the point
    var expectedValue = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("48966811922282644868055304540023198630821617313810671269304062775322461326085", 10),
        cryptoMath.stringToDigits("62766347176538165850925649571367125874094146714736151515015472701383455763403", 10)
        );

    // Double the point
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);
    ecOperator.convertToJacobianForm(point);
    ecOperator.convertToMontgomeryForm(point);
    ecOperator.double(point, point);

    // should be Jacobian on output
    if (point.isAffine === true) {
        ok(false, "point.isAffine == true");
    }

    // for comparison with results from Magma, we convert to Affine
    ecOperator.convertToAffineForm(point);
    ecOperator.convertToStandardForm(point);

    // NOTE: the test version of double converts the point to affine space
    if (point.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    if (point.isInfinity === false) {
        ok(false, "point.isInfinity == false");
    }

    ok(true);

});

test("eccTestMixedAdd", function () {
    expect(4);

    // USE NIST CURVE FOR TESTING
    var curve = cryptoECC.createP256();

    eccTests.mixedAddTestMainPath.call(this, curve);
    eccTests.mixedAddTestAdditiveInversePath.call(this, curve);
    eccTests.mixedAddTestSamePointPath.call(this, curve);
    eccTests.mixedAddTestInfinityPath.call(this, curve);
});

eccTests.mixedAddTestImpl = function (curve, point1, point2, expectedValue) {

    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);
    if (!point1.isInMontgomeryForm) {
        ecOperator.convertToMontgomeryForm(point1);
    }
    if (point1.isAffine) {
        ecOperator.convertToJacobianForm(point1);
    }
    if (!point2.isInMontgomeryForm) {
        ecOperator.convertToMontgomeryForm(point2);
    }

    ecOperator.mixedAdd(point1, point2, point1);

    // should be Jacobian on output
    if (point1.isAffine === true) {
        ok(false, "point.isAffine == true");
    }

    // for comparison with results from Magma, we convert to Affine
    ecOperator.convertToAffineForm(point1);
    ecOperator.convertToStandardForm(point1);

    // NOTE: the test version of double converts the point to affine space
    if (point1.isAffine === false) {
        ok(false, "point.isAffine == false");
    }

    // if both are infinity, then they're equal
    if (point1.isInfinity && expectedValue.isInfinity) {
        return;
    }

    if (cryptoMath.sequenceEqual(point1.x, expectedValue.x) === false) {
        ok(false, "point1.x != expectedValue.x");
    }

    if (cryptoMath.sequenceEqual(point1.y, expectedValue.y) === false) {
        ok(false, "point1.y != expectedValue.y");
    }

    ok(true);
};

eccTests.mixedAddTestMainPath = function (curve) {

    var point1, point2, expectedValue;

    // A random point on the curve, generated by using Magma
    point1 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
    );

    // A random point on the curve, generated by using Magma
    point2 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("47613893567070068258577018714129972946576730457691498223532169399056904097106", 10),
        cryptoMath.stringToDigits("69975134274942587319816459475221188408835613494163681846165872326255291661680", 10)
    );

    // point1 + point2, expected value
    expectedValue = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("66097792134656600823817223312287309419372601625565860808402773318104169602215", 10),
        cryptoMath.stringToDigits("61646566645364207673378446904589632855648536307496319296095244928900436905461", 10)
    );

    eccTests.mixedAddTestImpl(curve, point1, point2, expectedValue);
};

eccTests.mixedAddTestAdditiveInversePath = function (curve) {

    // A random point on the curve, generated by using Magma
    var point1 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );

    // A random point on the curve, generated by using Magma
    var point2 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("109182285551186135077151995958190207041745468772436442519275514403044065964758", 10)
        );

    // point1 + point2, expected value
    var expectedValue = curve.createPointAtInfinity();

    eccTests.mixedAddTestImpl(curve, point1, point2, expectedValue);
};

eccTests.mixedAddTestSamePointPath = function (curve) {

    // A random point on the curve, generated by using Magma
    var point1 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );

    // The exact same point
    var point2 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );

    // Expected point should P + P = 2 * P
    var expectedValue = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("48966811922282644868055304540023198630821617313810671269304062775322461326085", 10),
        cryptoMath.stringToDigits("62766347176538165850925649571367125874094146714736151515015472701383455763403", 10)
        );

    eccTests.mixedAddTestImpl(curve, point1, point2, expectedValue);
};

eccTests.mixedAddTestInfinityPath = function (curve) {

    // A random point on the curve, generated by using Magma
    var point1 = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );

    // Infinity
    var point2 = curve.createPointAtInfinity();

    // Expected point should P + Inf = P;
    var expectedValue = point1.clone();

    eccTests.mixedAddTestImpl(curve, point1, point2, expectedValue);

    eccTests.mixedAddTestImpl(curve, point2, point1, expectedValue);
};

test("ScalarParameterChecking1", function () {

    // USE NIST CURVE FOR TESTING
    var curve = cryptoECC.createP256();
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve); // A random point on the curve, generated by using Magma
    var point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );
    ecOperator.convertToMontgomeryForm(point);

    // Storage for output
    var result = curve.allocatePointStorage();
    ecOperator.convertToJacobianForm(result);
    ecOperator.convertToMontgomeryForm(result);

    // safe k = order - 1
    var safek = curve.order.slice();
    cryptoMath.subtract(safek, cryptoMath.intToDigits(1), safek);
    ecOperator.scalarMultiply(safek, point, result);

    // no exception or strange result expected
    ok(true);
});

test("ScalarParameterChecking2", function () {

    // USE NIST CURVE FOR TESTING
    var curve = cryptoECC.createP256();
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve); // A random point on the curve, generated by using Magma
    var point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );
    ecOperator.convertToMontgomeryForm(point);

    // Storage for output
    var result = curve.allocatePointStorage();
    ecOperator.convertToJacobianForm(result);
    ecOperator.convertToMontgomeryForm(result);

    // illegal k (k must be in the range 0 <= k < order)
    // we expect an exception when we try to multiply
    var illegalk = curve.order.slice();

    try {
        ecOperator.scalarMultiply(illegalk, point, result);
        ok(false, "Expected an error and didn't get one.");
    }
    catch (e) {
        if (e.message != "The scalar k must be in the range 1 <= k < order.") {
            ok(false, "Unexpected Error.");
        }
    }

    ok(true);
});

test("ScalarParameterChecking3", function () {

    // USE NIST CURVE FOR TESTING
    var curve = cryptoECC.createP256();
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve); // A random point on the curve, generated by using Magma
    var point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );
    ecOperator.convertToMontgomeryForm(point);

    // Storage for output
    var result = curve.allocatePointStorage();
    ecOperator.convertToJacobianForm(result);
    ecOperator.convertToMontgomeryForm(result);

    // safe k = order - 1
    var safek = cryptoMath.intToDigits(0, 256);
    ecOperator.scalarMultiply(safek, point, result);

    if (result.isInfinity === false) {
        ok(false, "result.isInfinity != true");
    }

    ok(true);

});

test("ScalarMultiplication", function () {

    // USE NIST CURVE FOR TESTING
    var i, k, expected, result, point;
    var curve = cryptoECC.createP256();
    var ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);

    // A random point on the curve, generated by using Magma
    point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );

    // Montgomeryize point1 for use the scalar multiply
    ecOperator.convertToMontgomeryForm(point);

    for (i = 1; i < 100; i += 1) {
        // Integer K to multiply by
        k = cryptoMath.intToDigits(i, 16);

        result = point.curve.allocatePointStorage();
        ecOperator.convertToJacobianForm(result);
        ecOperator.convertToMontgomeryForm(result);

        ecOperator.scalarMultiply(k, point, result);

        // convert back to normal Affine coords
        ecOperator.convertToAffineForm(result);
        ecOperator.convertToStandardForm(result);

        expected = eccTests.getScalarMultiplicationExpected(
                    k,
                    point,
                    ecOperator);

        if (result.equals(expected) === false) {
            ok(false, "result != expected");
        }
    }

    if (i !== 100) {
        ok(false, "dropped out of loop somehow.");
    }

    ok(true);
});

test("BN254ScalarMultiplication", function () {

    var i, k, result, curve, point, expected, ecOperator;

    // USE BN254 CURVE FOR TESTING
    curve = cryptoECC.createBN254();

    // A random point on the curve, generated by using Magma
    point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("16265663556941183235667673432237010020467740389186255294070246486864918269252", 10),
        cryptoMath.stringToDigits("2939044720388101534411915484259893450700762028171953183140911100854998190050", 10)
        );

    // Create EC operator
    ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);

    // Montgomeryize point1 for use the scalar multiply
    ecOperator.convertToMontgomeryForm(point);

    for (i = 1; i < 100; i += 1) {
        // Integer K to multiply by
        k = cryptoMath.intToDigits(i, 16);
        result = point.curve.allocatePointStorage();
        ecOperator.convertToJacobianForm(result);
        ecOperator.convertToMontgomeryForm(result);

        ecOperator.scalarMultiply(k, point, result);

        // convert back to normal Affine coords
        ecOperator.convertToAffineForm(result);
        ecOperator.convertToStandardForm(result);

        expected = eccTests.getScalarMultiplicationExpected(
                    k,
                    point,
                    ecOperator);

        if (result.equals(expected) === false) {
            ok(false, "result != expected");
        }
    }

    if (i !== 100) {
        ok(false, "dropped out of loop somehow.");
    }

    ok(true);
});

test("Precomputation", function () {

    var i, k, w, ecOperator, expected, result, curve, point, expectedPoints, precomputedPoints;

    // USE NIST CURVE FOR TESTING
    curve = cryptoECC.createP256();

    // A random point on the curve, generated by using Magma
    point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("41141545408281391351640436383732760700359269596702401355802682398622045375626", 10),
        cryptoMath.stringToDigits("6609803659170113685545450991217366488340674642853871676258116905823031889193", 10)
        );

    // Setup the point for table generation
    ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);
    ecOperator.convertToMontgomeryForm(point);

    // the "width" of the NAF used in scalar multiplication
    w = 5;

    // generate expected table
    expectedPoints = eccTests.getExpectedPrecomputationTable(
        ecOperator,
        point,
        w);

    // generate actual table then demontgomeryize the results for easier
    // testing/debugging
    precomputedPoints = ecOperator.generatePrecomputationTable(w, point);
    for (i = 0; i < precomputedPoints.length; i++) {
        ecOperator.convertToStandardForm(precomputedPoints[i]);
    }

    if (precomputedPoints.length !== expectedPoints.length) {
        ok(false, "precomputedPoints.length !== expectedPoints.length");
    }

    for (i = 0; i < precomputedPoints.length; i++) {
        if (precomputedPoints[i].equals(expectedPoints[i]) === false) {
            ok(false, "precomputedPoints[" + i + "] !== expectedPoints[" + i + "]");
            return;
        }
    }

    ok(true);
});

test("BN254Precomputation", function () {

    var i, w, ecOperator, curve, point, expectedPoints, precomputedPoints;

    // USE BN254 CURVE FOR TESTING
    curve = cryptoECC.createBN254();

    // A random point on the curve, generated by using Magma
    point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("16265663556941183235667673432237010020467740389186255294070246486864918269252", 10),
        cryptoMath.stringToDigits("2939044720388101534411915484259893450700762028171953183140911100854998190050", 10)
        );

    // Setup the point for table generation
    ecOperator = new cryptoECC.EllipticCurveOperatorFp(curve);
    ecOperator.convertToMontgomeryForm(point);

    // the "width" of the NAF used in scalar multiplication
    w = 5;

    // generate expected table
    expectedPoints = eccTests.getExpectedPrecomputationTable(
        ecOperator,
        point,
        w);

    // generate actual table then demontgomeryize the results for easier
    // testing/debugging
    precomputedPoints = ecOperator.generatePrecomputationTable(w, point);
    for (i = 0; i < precomputedPoints.length; i++) {
        ecOperator.convertToStandardForm(precomputedPoints[i]);
    }

    if (precomputedPoints.length !== expectedPoints.length) {
        ok(false, "precomputedPoints.length !== expectedPoints.length");
    }

    for (i = 0; i < precomputedPoints.length; i++) {
        if (precomputedPoints[i].equals(expectedPoints[i]) === false) {
            ok(false, "precomputedPoints[" + i + "] !== expectedPoints[" + i + "]");
        }
    }

    ok(true);
});

test("sec1EncodingFp", function () {

    var encodedPoint, decodedPoint, curve, point;

    // USE BN254 CURVE FOR TESTING
    curve = cryptoECC.createP256();

    // A random point on the curve, generated by using Magma
    point = new cryptoECC.EllipticCurvePointFp(
        curve,
        false,
        cryptoMath.stringToDigits("51341684110292169522690904331178805285423562017205921106734982126273988940428", 10),
        cryptoMath.stringToDigits("59391805948382381107556421949641352601431252340233665190507092459902302545373", 10)
    );

    sec1EncodingFp = new cryptoECC.sec1EncodingFp();
    encodedPoint = sec1EncodingFp.encodePoint(point);
    decodedPoint = sec1EncodingFp.decodePoint(encodedPoint, curve);

    if (point.equals(decodedPoint) === false) {
        ok(false, "points not equal");
        return;
    }

    ok(true);
});

test("JacobiSymbol", function () {

    var testVectorsJacobi = [];
    testVectorsJacobi.push(["16", "11", "3", "1"]); // bit-width, p, a, jacobi
    testVectorsJacobi.push(["16", "11", "2", "-1"]);
    testVectorsJacobi.push(["16", "11", "0", "0"]);
    testVectorsJacobi.push(["16", "11", "31", "1"]);
    testVectorsJacobi.push(["256", "101587441929941092738836754749231741144803906143861164671435562870648272335681", "101587441929941092738836754749231741144803906143861164671435562870648272335680", "1"]);
    testVectorsJacobi.push(["256", "101587441929941092738836754749231741144803906143861164671435562870648272335681", "0", "0"]);
    testVectorsJacobi.push(["256", "101587441929941092738836754749231741144803906143861164671435562870648272335681", "25", "1"]);
    testVectorsJacobi.push(["256", "101587441929941092738836754749231741144803906143861164671435562870648272335681", "244", "-1"]);

    function testJacobiSymbolImpl(p, a, expectedJacobi) {
        var rand = {};

        var slvr = new cryptoECC.ModularSquareRootSolver(p, rand);
        var actual = slvr.jacobiSymbol(a);

        if (expectedJacobi !== actual) {
            return false;
        }

        return true;
    }

    for (var i = 0; i < testVectorsJacobi.length; i++) {
        var testVector = testVectorsJacobi[i];

        var bitWidth = parseInt(testVector[0]);
        var p = cryptoMath.stringToDigits(testVector[1], 10);
        var a = cryptoMath.stringToDigits(testVector[2], 10);
        var expectedJacobi = parseInt(testVector[3]);

        if (!testJacobiSymbolImpl(p, a, expectedJacobi)) {
            ok(false, "testJacobiSymbolImpl");
            continue;
        }
    }

    ok(true);
});

test("ModularSquareRoot", function () {

    var testVectorsModSqrt = [];

    // GENERAL CASES THAT RUN QUICK AND ARE WORKING
    testVectorsModSqrt.push(["16", "11", "9", "3"]); // bit-width, p, a, sqrt(a)
    testVectorsModSqrt.push(["16", "11", "3", "5"]);
    testVectorsModSqrt.push(["16", "11", "0", "0"]);
    testVectorsModSqrt.push(["16", "11", "2", null]);

    // SPECIAL CASES FOR U-PROVE
    var p256CurveP = "115792089210356248762697446949407573530086143415290314195533631308867097853951";
    testVectorsModSqrt.push(["256", p256CurveP, "101587441929941092738836754749231741144803906143861164671435562870648272335678", "63845812921284976993223695054304154409581465067309839454320615519046705258161"]);
    testVectorsModSqrt.push(["256", p256CurveP, "3016174586572102263574869669413963627906116608609406572924847041132802741267", "109806596536464684398603240945762966095351774006516620697183690813593491770170"]);
    testVectorsModSqrt.push(["256", p256CurveP, "29670982684967209443892226119764400387024504828942602904814974251066989750387", "26776952009146560451669467340604384594324242216852150043299232050999417653961"]);
    testVectorsModSqrt.push(["256", p256CurveP, "19612420911575735833254891811218256869443368727469832246194174384320455660051", null]);
    testVectorsModSqrt.push(["256", p256CurveP, "100779581846099572129239457562190393778380478085124369051160362864001632055885", "104157250807150907522601542009050149485597291463630447342624171831904933867977"]);
    testVectorsModSqrt.push(["256", p256CurveP, "15833081183271089426244201379263086136300123781016700365421977604045725242800", "100701209358271874473297734722485422154447284817779153380796129598904191299385"]);
    testVectorsModSqrt.push(["256", p256CurveP, "56188044133488283357259590406054931034651141249339807499006297030384557317688", "83676071472259910869376872188855586197918175218795490502657442552838300079204"]);

    function testModSqrtlImpl(p, a, expectedSqrt) {
        var slvr = new cryptoECC.ModularSquareRootSolver(p);
        var actual = slvr.squareRoot(a);

        if (expectedSqrt === null && actual === null) {
            return true;
        }

        return (cryptoMath.compareDigits(expectedSqrt, actual) === 0);
    }

    for (var i = 0; i < testVectorsModSqrt.length; i++) {

        var testVector = testVectorsModSqrt[i];
        var p = cryptoMath.stringToDigits(testVector[1], 10);
        var a = cryptoMath.stringToDigits(testVector[2], 10);
        var expectedSqrt = (testVector[3] === null) ? null : cryptoMath.stringToDigits(testVector[3], 10);
        if (!testModSqrtlImpl(p, a, expectedSqrt)) {
            ok(false, "testModSqrtlImpl");
        }

    }

    ok(true);
});
