pragma circom 2.1.9;

include "potential.circom";
include "eddsaposeidon.circom";

// Controlled vertex-scaling Bellman upper-bound circuit (N in {8, 16, 32, 64}, slots=8)
// with identical sparse grid-neighborhood + EdDSA-Poseidon OBU streaming architecture
// to CausalUpper(396), enabling apples-to-apples monotonic N-scaling benchmarks (G6.2).
template ScaleUpper(n, bits, slots, E, edges, outOffsets, rateExact, rateUpper, shortCap, profileTag) {
    signal input relTag;
    signal input sid;
    signal input revision;
    signal input profile;
    signal input entry;
    signal input pkCommit;
    signal input deposit;
    signal input infraMask;
    signal input prevState;
    signal input nextState;
    signal input refundDelta;
    signal input charge;

    signal input Ax;
    signal input Ay;
    signal input keySalt;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input oldMask;
    signal input oldCount;
    signal input oldUpper;
    signal input oldRefund;
    signal input oldSalt;
    signal input newSalt;

    signal input past[slots];
    signal input fault[slots];
    signal input sealed[slots];
    signal input opened[slots];
    signal input measured[slots];
    signal input leafSalt[slots];
    signal input maximum[slots + 1];
    signal input phi[slots + 1][n];
    signal input live[slots + 1][n];
    signal input upper;

    relTag === 1;
    profile === profileTag;
    infraMask === 0;
    charge === 0;

    component identity = Poseidon(5);
    identity.inputs[0] <== 207001;
    identity.inputs[1] <== sid;
    identity.inputs[2] <== profile;
    identity.inputs[3] <== entry;
    identity.inputs[4] <== pkCommit;

    component pk = Poseidon(3);
    pk.inputs[0] <== Ax;
    pk.inputs[1] <== Ay;
    pk.inputs[2] <== keySalt;
    pk.out === pkCommit;

    component prior = Poseidon(8);
    prior.inputs[0] <== 207002;
    prior.inputs[1] <== identity.out;
    prior.inputs[2] <== revision;
    prior.inputs[3] <== oldMask;
    prior.inputs[4] <== oldCount;
    prior.inputs[5] <== oldUpper;
    prior.inputs[6] <== oldRefund;
    prior.inputs[7] <== oldSalt;
    prior.out === prevState;

    component revRange = Num2Bits(32);
    revRange.in <== revision + 1;
    component priorBits = Num2Bits(slots);
    priorBits.in <== oldMask;

    component path[slots + 1];
    for (var i = 0; i <= slots; i++) {
        path[i] = Vertex(n, bits);
        path[i].index <== maximum[i];
    }
    maximum[0] === entry;

    component header = Poseidon(3);
    header.inputs[0] <== 207003;
    header.inputs[1] <== identity.out;
    header.inputs[2] <== slots;

    component checkpoint[slots];
    component leaf[slots];
    component dRange[slots];
    component dCap[slots];
    component edgeSlack[slots - 1][E];
    component pathPhiSel[slots + 1];
    component openedSlack[slots];

    signal valid[slots];
    signal edgeMatch[slots][E];
    signal enEdge[slots - 1][E];
    signal pathOpenFee[slots];
    signal pathCost[slots];
    signal selectOpen[slots][n];
    signal reachUnopened[slots][n];

    var count = 0;
    var mask = 0;
    var total = 0;

    for (var u = 0; u < n; u++) {
        phi[slots][u] === 0;
        live[slots][u] === 1;
    }

    for (var i = 0; i < slots; i++) {
        past[i] * (past[i] - 1) === 0;
        fault[i] * (fault[i] - 1) === 0;
        fault[i] * (1 - past[i]) === 0;
        if (i > 0) {
            past[i] * (1 - past[i - 1]) === 0;
        }
        valid[i] <== past[i] - fault[i];
        opened[i] * (opened[i] - 1) === 0;
        opened[i] * (1 - valid[i]) === 0;
        priorBits.out[i] * (1 - opened[i]) === 0;
        (1 - valid[i]) * sealed[i] === 0;
        (1 - opened[i]) * measured[i] === 0;

        dRange[i] = Num2Bits(9);
        dRange[i].in <== measured[i];
        dCap[i] = Num2Bits(9);
        dCap[i].in <== shortCap - measured[i];

        leaf[i] = Poseidon(6);
        leaf[i].inputs[0] <== 207010 + i;
        leaf[i].inputs[1] <== identity.out;
        leaf[i].inputs[2] <== maximum[i];
        leaf[i].inputs[3] <== maximum[i + 1];
        leaf[i].inputs[4] <== measured[i];
        leaf[i].inputs[5] <== leafSalt[i];
        opened[i] * (leaf[i].out - sealed[i]) === 0;

        checkpoint[i] = Poseidon(4);
        checkpoint[i].inputs[0] <== (i == 0) ? header.out : checkpoint[i - 1].out;
        checkpoint[i].inputs[1] <== past[i];
        checkpoint[i].inputs[2] <== fault[i];
        checkpoint[i].inputs[3] <== sealed[i];

        var legalSum = 0;
        for (var e = 0; e < E; e++) {
            edgeMatch[i][e] <== path[i].select[edges[e][0]] * path[i + 1].select[edges[e][1]];
            legalSum += edgeMatch[i][e];
        }
        legalSum === 1;

        var exR = 0;
        var hiR = 0;
        for (var u = 0; u < n; u++) {
            exR += path[i].select[u] * rateExact[i][u];
            hiR += path[i].select[u] * rateUpper[i][u];
        }
        pathOpenFee[i] <== measured[i] * exR;
        pathCost[i] <== pathOpenFee[i] + (1 - opened[i]) * (shortCap * hiR);
        total += pathCost[i];

        if (i < slots - 1) {
            for (var e = 0; e < E; e++) {
                var u = edges[e][0];
                var v = edges[e][1];
                enEdge[i][e] <== (1 - opened[i]) * live[i + 1][v];
                edgeSlack[i][e] = BoundedSlack(16);
                edgeSlack[i][e].enable <== enEdge[i][e];
                edgeSlack[i][e].left <== phi[i][u];
                edgeSlack[i][e].right <== phi[i + 1][v] + shortCap * rateUpper[i][u];
            }
        }

        for (var u = 0; u < n; u++) {
            live[i][u] * (live[i][u] - 1) === 0;
            selectOpen[i][u] <== opened[i] * path[i].select[u];
            if (i < slots - 1) {
                var outLive = 0;
                for (var e = outOffsets[u]; e < outOffsets[u + 1]; e++) {
                    outLive += live[i + 1][edges[e][1]];
                }
                reachUnopened[i][u] <== (1 - opened[i]) * outLive;
                (1 - live[i][u]) * (selectOpen[i][u] + reachUnopened[i][u]) === 0;
            } else {
                reachUnopened[i][u] <== 1 - opened[i];
                (1 - live[i][u]) * (selectOpen[i][u] + reachUnopened[i][u]) === 0;
                (1 - opened[i]) * (phi[i][u] - shortCap * rateUpper[i][u]) === 0;
            }
        }

        count += past[i];
        mask += opened[i] * (2 ** i);
    }

    for (var i = 0; i <= slots; i++) {
        pathPhiSel[i] = SelectSignal(n);
        for (var u = 0; u < n; u++) {
            pathPhiSel[i].select[u] <== path[i].select[u];
            pathPhiSel[i].values[u] <== phi[i][u];
        }
    }
    for (var i = 0; i < slots; i++) {
        openedSlack[i] = BoundedSlack(16);
        openedSlack[i].enable <== opened[i];
        openedSlack[i].left <== pathPhiSel[i].out;
        openedSlack[i].right <== pathPhiSel[i + 1].out + pathOpenFee[i];
    }

    pathPhiSel[0].out === upper;
    total === upper;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.S <== S;
    sig.M <== checkpoint[slots - 1].out;

    component cnt0 = Num2Bits(4);
    cnt0.in <== oldCount;
    component cntDiff = Num2Bits(4);
    cntDiff.in <== count - oldCount;

    component next = Poseidon(8);
    next.inputs[0] <== 207002;
    next.inputs[1] <== identity.out;
    next.inputs[2] <== revision + 1;
    next.inputs[3] <== mask;
    next.inputs[4] <== count;
    next.inputs[5] <== upper;
    next.inputs[6] <== oldRefund + refundDelta;
    next.inputs[7] <== newSalt;
    next.out === nextState;

    component amt[7];
    amt[0] = Num2Bits(32); amt[0].in <== deposit;
    amt[1] = Num2Bits(32); amt[1].in <== oldRefund;
    amt[2] = Num2Bits(32); amt[2].in <== oldUpper;
    amt[3] = Num2Bits(16); amt[3].in <== upper;
    amt[4] = Num2Bits(32); amt[4].in <== oldUpper - upper;
    amt[5] = Num2Bits(32); amt[5].in <== refundDelta;
    amt[6] = Num2Bits(32); amt[6].in <== deposit - upper - oldRefund - refundDelta;
}
