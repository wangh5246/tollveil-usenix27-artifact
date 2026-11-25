pragma circom 2.1.9;

include "potential.circom";
include "eddsaposeidon.circom";

// Exact coupled Bellman upper-bound settlement circuit for a sparse directed
// multi-interchange highway gantry corridor (Taiwan TDCS M06A) with statutory
// 3-class mileage tariff (Small/Large/Trailer, 0.1 TWD integer units),
// EdDSA-Poseidon OBU streaming checkpoints, and corroborated gantry-outage waiver.
template M06ACorridor(n, bits, slots, E, edges, outOffsets, feeSmall, feeLarge, feeTrailer, profileTag, rel) {
    // Public inputs (13)
    signal input relTag;
    signal input sid;
    signal input revision;
    signal input profile;
    signal input vehClass;      // 0 = small (31/32), 1 = large (41/42), 2 = trailer (5)
    signal input entry;
    signal input pkCommit;
    signal input deposit;
    signal input infraMask;
    signal input prevState;
    signal input nextState;
    signal input refundDelta;
    signal input charge;

    // Private inputs: OBU key, signature, predecessor state
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

    // Private inputs: streaming checkpoint & primal-dual Bellman certificate
    signal input past[slots];
    signal input fault[slots];
    signal input sealed[slots];
    signal input opened[slots];
    signal input leafSalt[slots];
    signal input maximum[slots + 1];
    signal input phi[slots + 1][n];
    signal input live[slots + 1][n];
    signal input upper;

    assert(rel == 1 || rel == 2);
    relTag === rel;
    profile === profileTag;
    if (rel == 1) {
        infraMask === 0;
        charge === 0;
    } else {
        charge === upper;
        refundDelta === deposit - oldRefund - charge;
        nextState === 0;
    }

    // Statutory vehicle class selector (0=small, 1=large, 2=trailer)
    signal isLarge;
    signal isTrailer;
    isLarge <-- (vehClass == 1) ? 1 : 0;
    isTrailer <-- (vehClass == 2) ? 1 : 0;
    isLarge * (isLarge - 1) === 0;
    isTrailer * (isTrailer - 1) === 0;
    isLarge * isTrailer === 0;
    vehClass === isLarge + 2 * isTrailer;

    signal effFee[n];
    for (var u = 0; u < n; u++) {
        effFee[u] <== feeSmall[u]
            + isLarge * (feeLarge[u] - feeSmall[u])
            + isTrailer * (feeTrailer[u] - feeSmall[u]);
    }

    // Session identity & OBU key commitment
    component identity = Poseidon(6);
    identity.inputs[0] <== 206001;
    identity.inputs[1] <== sid;
    identity.inputs[2] <== profile;
    identity.inputs[3] <== vehClass;
    identity.inputs[4] <== entry;
    identity.inputs[5] <== pkCommit;

    component pk = Poseidon(3);
    pk.inputs[0] <== Ax;
    pk.inputs[1] <== Ay;
    pk.inputs[2] <== keySalt;
    pk.out === pkCommit;

    // Predecessor state commitment
    component prior = Poseidon(8);
    prior.inputs[0] <== 206002;
    prior.inputs[1] <== identity.out;
    prior.inputs[2] <== revision;
    prior.inputs[3] <== oldMask;
    prior.inputs[4] <== oldCount;
    prior.inputs[5] <== oldUpper;
    prior.inputs[6] <== oldRefund;
    prior.inputs[7] <== oldSalt;
    prior.out === prevState;

    component revRange = Num2Bits(32);
    revRange.in <== revision + (2 - rel);
    component infra = Num2Bits(slots);
    infra.in <== infraMask;
    component priorBits = Num2Bits(slots);
    priorBits.in <== oldMask;

    // One-hot selectors for primal maximizing path
    component path[slots + 1];
    for (var i = 0; i <= slots; i++) {
        path[i] = Vertex(n, bits);
        path[i].index <== maximum[i];
    }
    maximum[0] === entry;

    // Streaming OBU checkpoint hash chain
    component header = Poseidon(3);
    header.inputs[0] <== 206003;
    header.inputs[1] <== identity.out;
    header.inputs[2] <== slots;

    component checkpoint[slots];
    component leaf[slots];
    component edgeSlack[slots][E];
    component pathFeeSel[slots];
    component pathPhiSel[slots + 1];
    component openedSlack[slots];

    signal valid[slots];
    signal excuse[slots];
    signal edgeMatch[slots][E];
    signal slotUnwaivedFee[slots][n];
    signal enEdge[slots][E];
    signal pathSlotFee[slots];
    signal selectOpen[slots][n];
    signal reachUnopened[slots][n];

    var count = 0;
    var mask = 0;
    var total = 0;

    // Terminal boundary: all vertices admissible at slot = slots with 0 potential
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

        // Joint corroborated waiver: M = F & M_infra
        excuse[i] <== fault[i] * infra.out[i];

        // Opened slot leaf binds (u_i, v_i) to OBU-sealed commitment
        leaf[i] = Poseidon(5);
        leaf[i].inputs[0] <== 206010 + i;
        leaf[i].inputs[1] <== identity.out;
        leaf[i].inputs[2] <== maximum[i];
        leaf[i].inputs[3] <== maximum[i + 1];
        leaf[i].inputs[4] <== leafSalt[i];
        opened[i] * (leaf[i].out - sealed[i]) === 0;

        checkpoint[i] = Poseidon(4);
        checkpoint[i].inputs[0] <== (i == 0) ? header.out : checkpoint[i - 1].out;
        checkpoint[i].inputs[1] <== past[i];
        checkpoint[i].inputs[2] <== fault[i];
        checkpoint[i].inputs[3] <== sealed[i];

        // Verify primal transition (maximum[i], maximum[i+1]) is a legal directed edge in E
        var legalEdgeSum = 0;
        for (var e = 0; e < E; e++) {
            edgeMatch[i][e] <== path[i].select[edges[e][0]] * path[i + 1].select[edges[e][1]];
            legalEdgeSum += edgeMatch[i][e];
        }
        legalEdgeSum === 1;

        // Per-vertex fee on layer i (waived iff excuse[i] == 1; note opened[i] => excuse[i] == 0)
        for (var u = 0; u < n; u++) {
            slotUnwaivedFee[i][u] <== (1 - excuse[i]) * effFee[u];
        }

        // Primal path fee on slot i
        pathFeeSel[i] = SelectSignal(n);
        for (var u = 0; u < n; u++) {
            pathFeeSel[i].select[u] <== path[i].select[u];
            pathFeeSel[i].values[u] <== slotUnwaivedFee[i][u];
        }
        pathSlotFee[i] <== pathFeeSel[i].out;
        total += pathSlotFee[i];

        // Dual Bellman upper-bound potential inequalities over all directed edges
        for (var e = 0; e < E; e++) {
            var u = edges[e][0];
            var v = edges[e][1];
            enEdge[i][e] <== (1 - opened[i]) * live[i + 1][v];
            edgeSlack[i][e] = BoundedSlack(15);
            edgeSlack[i][e].enable <== enEdge[i][e];
            edgeSlack[i][e].left <== phi[i][u];
            edgeSlack[i][e].right <== phi[i + 1][v] + slotUnwaivedFee[i][u];
        }

        // Backward liveness propagation
        for (var u = 0; u < n; u++) {
            live[i][u] * (live[i][u] - 1) === 0;
            selectOpen[i][u] <== opened[i] * path[i].select[u];
            var outLive = 0;
            for (var e = outOffsets[u]; e < outOffsets[u + 1]; e++) {
                outLive += live[i + 1][edges[e][1]];
            }
            reachUnopened[i][u] <== (1 - opened[i]) * outLive;
            (1 - live[i][u]) * (selectOpen[i][u] + reachUnopened[i][u]) === 0;
        }

        count += past[i];
        mask += opened[i] * (2 ** i);
    }

    // Select potentials along primal path and check opened-layer Bellman inequality
    for (var i = 0; i <= slots; i++) {
        pathPhiSel[i] = SelectSignal(n);
        for (var u = 0; u < n; u++) {
            pathPhiSel[i].select[u] <== path[i].select[u];
            pathPhiSel[i].values[u] <== phi[i][u];
        }
    }
    for (var i = 0; i < slots; i++) {
        openedSlack[i] = BoundedSlack(15);
        openedSlack[i].enable <== opened[i];
        openedSlack[i].left <== pathPhiSel[i].out;
        openedSlack[i].right <== pathPhiSel[i + 1].out + pathSlotFee[i];
    }

    // Primal-dual tightness locks exact coupled upper bound
    pathPhiSel[0].out === upper;
    total === upper;

    // Verify OBU EdDSA-Poseidon signature over streaming checkpoint
    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.S <== S;
    sig.M <== checkpoint[slots - 1].out;

    // Monotonic elapsed counter & state transition
    component cnt0 = Num2Bits(4);
    cnt0.in <== oldCount;
    component cntDiff = Num2Bits(4);
    cntDiff.in <== count - oldCount;
    if (rel == 1) {
        component next = Poseidon(8);
        next.inputs[0] <== 206002;
        next.inputs[1] <== identity.out;
        next.inputs[2] <== revision + 1;
        next.inputs[3] <== mask;
        next.inputs[4] <== count;
        next.inputs[5] <== upper;
        next.inputs[6] <== oldRefund + refundDelta;
        next.inputs[7] <== newSalt;
        next.out === nextState;
    } else {
        count === slots;
    }

    // Escrow conservation range guards
    component amt[7];
    amt[0] = Num2Bits(32); amt[0].in <== deposit;
    amt[1] = Num2Bits(32); amt[1].in <== oldRefund;
    amt[2] = Num2Bits(32); amt[2].in <== oldUpper;
    amt[3] = Num2Bits(15); amt[3].in <== upper;
    amt[4] = Num2Bits(32); amt[4].in <== oldUpper - upper;
    amt[5] = Num2Bits(32); amt[5].in <== refundDelta;
    amt[6] = Num2Bits(32); amt[6].in <== deposit - upper - oldRefund - refundDelta;
}
