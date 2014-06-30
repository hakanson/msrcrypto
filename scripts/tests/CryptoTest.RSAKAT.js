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

/// <reference path="~/scripts/cryptoMath.js" />
/// <reference path="~/scripts/rsa-base.js" />
/// <reference path="~/scripts/rsa.js" />
/// <reference path="~/scripts/qunit/qunit-1.14.0.js" />

var cryptoMath = cryptoMath || msrCrypto.cryptoMath;
var mathRSAKATs = mathRSAKATs || {};

module("cryptoMath-RSAKAT");
mathRSAKATs.testDescription = "Math RSA KAT";

// Numbers computed in Maple
mathRSAKATs.p0 = cryptoMath.stringToDigits("61");
mathRSAKATs.q0 = cryptoMath.stringToDigits("67");
mathRSAKATs.e0 = cryptoMath.stringToDigits("7");
mathRSAKATs.d0 = cryptoMath.stringToDigits("2263");
mathRSAKATs.dp0 = cryptoMath.stringToDigits("43");
mathRSAKATs.dq0 = cryptoMath.stringToDigits("19");
mathRSAKATs.qinv0 = cryptoMath.stringToDigits("51");
mathRSAKATs.n0 = cryptoMath.stringToDigits("4087");
mathRSAKATs.m0 = cryptoMath.stringToDigits("3359");
mathRSAKATs.c0 = cryptoMath.stringToDigits("2720");
mathRSAKATs.m2 = cryptoMath.stringToDigits("2487");
mathRSAKATs.c2 = cryptoMath.stringToDigits("3402");

mathRSAKATs.p1 = cryptoMath.stringToDigits("179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624218582039");
mathRSAKATs.q1 = cryptoMath.stringToDigits("179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639474124377767893424865485276302219601246094119453082952085005768838150682342462881473913110540827237163350510684586298239947245938479716304835356329624218583163");
mathRSAKATs.e1 = cryptoMath.stringToDigits("65537");
mathRSAKATs.d1 = cryptoMath.stringToDigits("14351498309343356523490635383783973661546380885597440335552765206260243269628013130836189478934996619424087882183666020100963664029721955041449037750510258814758702029356366483883878653697002226470428330676257724752853513761307435240156490190686336960431637409061516730521690171161499294958789767979962644256835188367752099485264179584332437506886024436170604400262042023818027359679217593131459795618977415080681257733833245797448253712633717432670078128016690158168126847929889620136150214211102270878481560470358531683054505836984334246905598943376333910306592768181815747728896822160571258992601983440749585199425");
mathRSAKATs.dp1 = cryptoMath.stringToDigits("46499678078316034099557778955789168384716947292414942736151894895797554362495267208228544296648497041824132482286034762028042238139402026099741362042821083608525280823631226733049654800804488876710387448368784317154345337245669328268699742891620051640952711554161876920878064500192382177999740001827818688721");
mathRSAKATs.dq1 = cryptoMath.stringToDigits("19253258638019127143982777872267825206012756786542029439892057000566483840865637124501896674031135012775105349997975341828387710565152360853827549562208658910349159161223901630443341614372741117604424817136650372941620453169381371821496194865283219824672432892795081058733077791815144555650081115669505626367");
mathRSAKATs.qinv1 = cryptoMath.stringToDigits("5917673130774527454269065129821522699632130624632147970744584522096182388615245227678126032855052342332245741597189994869550908759905173516223625385818988080051078342277600493970802602532122315320074794686072253956415992212340859977344114848763885920857623572357378144909295462387677494020380946793679793181");
mathRSAKATs.n1 = cryptoMath.stringToDigits("32317006071311007300714876688669951960444102669715484032130345427524655138867890893197201411522913463688717960921898019494119559150490921095088152386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607552399123928388423263872741093180057774507870840424411016798511281620350417305740756987447243797535152734183392785208523225920039231153600534944970726549688941814648106526000812453366315824154818096350580756671696954751272019348086341197909436242198470511692221525127149789608791233435502321341586186982107958102322401459609357");
mathRSAKATs.m1 = cryptoMath.stringToDigits("31890151060914475693971419229528418363903267446639630144309623704700692284188061392193938380266540651318412546364796741792887474305297304292520698650791691193588018430040757950646209333737907613269094549568004266902750751055085337014216938093898448123378986465747976651160752521954968252109817870988547950474106620444089732726100286248696967726477945064454073552965969907618923321280049619581830371424872307128811836328802624334103000960561603960818951854451420515709274694351529017737746210057837529206739246180712320551711911308075327517122086975328364576052853143353005142899254737937092766611532051906049283613306");
mathRSAKATs.c1 = cryptoMath.stringToDigits("11876385313787872724640486578080180450972533519808507136363516904921943307470552052840654401070046392542373524840249590146949754941812840531981740820508256710072114071566322946320750920023230739591498665228804577237993475228229590487716107379837122619665303564748081285638931790117763148179603234138764896312948802876842682745131254540975228513050638851811155811423362360058373402037221176975395301746394917450639830677730026334252487484404173951704679232575292859214812730517665337651320467081849031889302608631285635452133008899453506497411750251277841398523733916949794010133213074892910471633412826665978897107226");

mathRSAKATs.p3 = cryptoMath.stringToDigits("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171");
mathRSAKATs.q3 = cryptoMath.stringToDigits("13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084241");
mathRSAKATs.e3 = cryptoMath.stringToDigits("7");
mathRSAKATs.d3 = cryptoMath.stringToDigits("154087982988198506376797587781916405738683741052197706234368640992342293547572254113750123419206459446674383325604051449421819801840928533565297797690980326239911389352314164926072995836315901103887404651864013861628184594486587641184162216403852247523360232254003673313457169387085189134643153312949328983543");
mathRSAKATs.dp3 = cryptoMath.stringToDigits("11492406797093654656777735712747868109268027846222051466620195523190083454348754551544463684143060080877170164159845186446074756695954202811228842005215003");
mathRSAKATs.dq3 = cryptoMath.stringToDigits("11492406797093654656777735712747868109268027846222051466620195523190083454348754551544463684143060080877170164159845186446074756695954202811228842005215063");
mathRSAKATs.qinv3 = cryptoMath.stringToDigits("11300866683808760412498106784202070307446894048785017275509858931136915396776275309018722622740675746195883994757181100005306844084354966097708361305128087");
mathRSAKATs.n3 = cryptoMath.stringToDigits("179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639477074095512480796227391561801824887394139579933613278628104952355769470429079061808809522886423955917442317693387325171135071792698344550223571732405562649211");
mathRSAKATs.m3 = cryptoMath.stringToDigits("176537431815172002555130320878442281983447543113388197382434902302774285520763423390743648225243451329880596474630649468261878894083432770160377615105387148956127735234915019698908542144523552580562116201183781240797245887271514599243382338587346905095769786018299846610537130383263285301830980630972751662218");
mathRSAKATs.c3 = cryptoMath.stringToDigits("134327232343803729632998224241729515090793916007258596348262967884367444466724471912403551965358016224420016164750098397986744461589433027707587545153785499253160286278662384965274250792829524920835605131016014118323823813809048441345782191651647723332223703435805635858773572044362285097450259265109030706479");

mathRSAKATs.kat = [
    { p: mathRSAKATs.p0, q: mathRSAKATs.q0, n: mathRSAKATs.n0, e: mathRSAKATs.e0, d: mathRSAKATs.d0, dp: mathRSAKATs.dp0, dq: mathRSAKATs.dq0, qinv: mathRSAKATs.qinv0, m: mathRSAKATs.m0, c: mathRSAKATs.c0 },
    { p: mathRSAKATs.p0, q: mathRSAKATs.q0, n: mathRSAKATs.n0, e: mathRSAKATs.e0, d: mathRSAKATs.d0, dp: mathRSAKATs.dp0, dq: mathRSAKATs.dq0, qinv: mathRSAKATs.qinv0, m: mathRSAKATs.m2, c: mathRSAKATs.c2 },
    //{ p: mathRSAKATs.p1, q: mathRSAKATs.q1, n: mathRSAKATs.n1, e: mathRSAKATs.e1, d: mathRSAKATs.d1, dp: mathRSAKATs.dp1, dq: mathRSAKATs.dq1, qinv: mathRSAKATs.qinv1, m: mathRSAKATs.m1, c: mathRSAKATs.c1 },
    { p: mathRSAKATs.p3, q: mathRSAKATs.q3, n: mathRSAKATs.n3, e: mathRSAKATs.e3, d: mathRSAKATs.d3, dp: mathRSAKATs.dp3, dq: mathRSAKATs.dq3, qinv: mathRSAKATs.qinv3, m: mathRSAKATs.m3, c: mathRSAKATs.c3 }
];

test("RSA KAT Raw Encrypt", function () {
    // RSA with CRT
    // c = m^e mod n
    // m = c^d mod n
    // m1 = c^dp mod p-1
    // m2 = c^dq mod q-1
    // qInv = q^-1 mod p
    // m = ((m1-m2)^qInv mod p)*q + m2
    var numberOfTests = mathRSAKATs.kat.length;
    expect(numberOfTests);

    var paddingMode = "raw";
    for (var i = 0; i < numberOfTests; ++i) {
        var kat = mathRSAKATs.kat[i];
        var keyStruct = {
            e: cryptoMath.digitsToBytes(kat.e), n: cryptoMath.digitsToBytes(kat.n), d: cryptoMath.digitsToBytes(kat.d),
            p: cryptoMath.digitsToBytes(kat.p), q: cryptoMath.digitsToBytes(kat.q),
            dp: cryptoMath.digitsToBytes(kat.dp), dq: cryptoMath.digitsToBytes(kat.dq), qi: cryptoMath.digitsToBytes(kat.qinv)
        };
        var rsa = msrcryptoRsa(keyStruct, paddingMode);

        var m = cryptoMath.digitsToBytes(kat.m);
        var c = cryptoMath.digitsToBytes(kat.c);
        var cc = cryptoMath.bytesToDigits(rsa.encrypt(m));
        var mm = cryptoMath.bytesToDigits(rsa.decrypt(c));

        // Verify results
        var pass = cryptoMath.compareDigits(cc, kat.c) === 0 &&
            cryptoMath.compareDigits(mm, kat.m) === 0;
        ok(pass, "RSA Raw Encrypt test. " +
            "c=" + kat.c.toString() + "\n" +
            "cc=" + cc.toString() + "\n" +
            "m=" + kat.m.toString() + "\n" +
            "mm=" + mm.toString()
            );
    }
});