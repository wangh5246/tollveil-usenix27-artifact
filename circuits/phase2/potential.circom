pragma circom 2.1.9;

include "poseidon.circom";
include "bitify.circom";

// Restrict the index to [0, n) and produce a shared one-hot selector.
// Every coefficient is boolean by induction, starting from the root.
template Vertex(n, bits) {
    signal input index;
    signal output select[n];
    signal tree[2 ** (bits + 1) - 1];
    component binary = Num2Bits(bits);
    binary.in <== index;
    tree[0] <== 1;
    for (var level = 0; level < bits; level++) {
        for (var node = (2 ** level) - 1; node < (2 ** (level + 1)) - 1; node++) {
            tree[2 * node + 2] <== tree[node] * binary.out[bits - level - 1];
            tree[2 * node + 1] <== tree[node] - tree[2 * node + 2];
        }
    }
    for (var v = 0; v < n; v++) {
        select[v] <== tree[2 ** bits - 1 + v];
    }
    for (var v = n; v < 2 ** bits; v++) {
        tree[2 ** bits - 1 + v] === 0;
    }
}

template SelectSignal(n) {
    signal input select[n];
    signal input values[n];
    signal output out;
    signal terms[n];
    var sum = 0;
    for (var v = 0; v < n; v++) {
        terms[v] <== select[v] * values[v];
        sum += terms[v];
    }
    out <== sum;
}

// Check an affine difference only on its active branch. The field equality
// ties the boolean decomposition to the actual difference, never to a
// witness hint. An inactive branch contributes the canonical zero slack.
template BoundedSlack(bits) {
    signal input enable;
    signal input left;
    signal input right;
    signal digit[bits];
    var sum = 0;
    for (var k = 0; k < bits; k++) {
        digit[k] <-- ((enable * (left - right)) >> k) & 1;
        digit[k] * (digit[k] - 1) === 0;
        sum += digit[k] * (2 ** k);
    }
    enable * (left - right) === sum;
}

// A static row partition of a Boolean adjacency matrix. groupOf[u] is
// the unique block containing u. targets[j] contains the exact distinct
// successor set for a block. Empty rows are allowed.
template PotentialLayer(n, bits, g, memberships, groupOf, targets, offsets,
                        rLo, rHi, rExact, dLo, dHi, distanceBits, slackBits, zeroTargets) {
    signal input isOpen;
    signal input measuredDistance;
    signal input originMax[n];
    signal input originMin[n];
    signal input targetMax[n];
    signal input targetMin[n];
    signal input hubMax[g];
    signal input hubMin[g];
    signal input fromMax[n];
    signal input toMax[n];
    signal input fromMin[n];
    signal input toMin[n];
    signal output feeMax;
    signal output feeMin;

    isOpen * (isOpen - 1) === 0;
    (1 - isOpen) * measuredDistance === 0;
    component capLo = Num2Bits(distanceBits);
    component capHi = Num2Bits(distanceBits);
    capLo.in <== measuredDistance - isOpen * dLo;
    capHi.in <== isOpen * dHi - measuredDistance;

    // The chosen source and destination must belong to a legal pair.
    // The per-group products sum to exactly one on a legal selected pair.
    signal groupChoices[g][2];
    signal vertexPair[g][2];
    var legal[2] = [0, 0];
    for (var j = 0; j < g; j++) {
        var from[2] = [0, 0];
        var to[2] = [0, 0];
        for (var v = 0; v < n; v++) {
            if (groupOf[v] == j) {
                from[0] += fromMax[v];
                from[1] += fromMin[v];
            }
        }
        for (var k = offsets[j]; k < offsets[j + 1]; k++) {
            to[0] += toMax[targets[k]];
            to[1] += toMin[targets[k]];
        }
        for (var p = 0; p < 2; p++) {
            groupChoices[j][p] <== from[p];
            vertexPair[j][p] <== groupChoices[j][p] * to[p];
            legal[p] += vertexPair[j][p];
        }
    }
    legal[0] === 1;
    legal[1] === 1;

    // Raw potentials can be signed field representatives. Soundness uses
    // bounded nonnegative integer slacks on the edges of every legal path,
    // together with the endpoint slacks. It never compares field order.
    // The equality at the source is a complete normal form for a row
    // partition: for every source, choose its fee plus its block optimum.
    if (zeroTargets == 1) {
        // In the all-exits terminal layer every successor potential is zero.
        // Empty rows must keep a free hub so dead ends retain their filler.
        for (var j = 0; j < g; j++) {
            if (offsets[j] < offsets[j + 1]) {
                (1 - isOpen) * hubMax[j] === 0;
                (1 - isOpen) * hubMin[j] === 0;
            }
        }
    } else {
        component diffMax[memberships];
        component diffMin[memberships];
        for (var j = 0; j < g; j++) {
            for (var k = offsets[j]; k < offsets[j + 1]; k++) {
                var v = targets[k];
                diffMax[k] = BoundedSlack(slackBits);
                diffMax[k].enable <== 1 - isOpen;
                diffMax[k].left <== hubMax[j];
                diffMax[k].right <== targetMax[v];
                diffMin[k] = BoundedSlack(slackBits);
                diffMin[k].enable <== 1 - isOpen;
                diffMin[k].left <== targetMin[v];
                diffMin[k].right <== hubMin[j];
            }
        }
    }
    for (var u = 0; u < n; u++) {
        (1 - isOpen) * (originMax[u] - hubMax[groupOf[u]] - dHi * rHi[u]) === 0;
        (1 - isOpen) * (originMin[u] - hubMin[groupOf[u]] - dLo * rLo[u]) === 0;
    }
    component edgeMaxIn = SelectSignal(n);
    component edgeMaxOut = SelectSignal(n);
    component edgeMinIn = SelectSignal(n);
    component edgeMinOut = SelectSignal(n);
    var exactRate = 0;
    var maxFee = 0;
    var minFee = 0;
    for (var v = 0; v < n; v++) {
        edgeMaxIn.select[v] <== fromMax[v];
        edgeMinIn.select[v] <== fromMax[v];
        edgeMaxOut.select[v] <== toMax[v];
        edgeMinOut.select[v] <== toMax[v];
        edgeMaxIn.values[v] <== originMax[v];
        edgeMinIn.values[v] <== originMin[v];
        edgeMaxOut.values[v] <== targetMax[v];
        edgeMinOut.values[v] <== targetMin[v];
        exactRate += fromMax[v] * rExact[v];
        maxFee += fromMax[v] * (dHi * rHi[v]);
        minFee += fromMin[v] * (dLo * rLo[v]);
    }
    signal exactFee <== exactRate * measuredDistance;
    component openedMax = Num2Bits(slackBits);
    component openedMin = Num2Bits(slackBits);
    openedMax.in <== isOpen * (edgeMaxIn.out - edgeMaxOut.out - exactFee);
    openedMin.in <== isOpen * (edgeMinOut.out + exactFee - edgeMinIn.out);
    feeMax <== maxFee + isOpen * (exactFee - maxFee);
    feeMin <== minFee + isOpen * (exactFee - minFee);
}

template Envelope(n, slots, bits, g, memberships, groupOf, targets, offsets,
                  rLo, rHi, rExact, dLo, dHi, exitFlags,
                  distanceBits, slackBits, amountBits, policy) {
    signal input session;
    signal input profile;
    signal input entry;
    signal input evidence;
    signal input summary;
    signal input open[slots];
    signal input source[slots];
    signal input destination[slots];
    signal input measured[slots];
    signal input evidenceSalt;
    signal input maximum[slots + 1];
    signal input minimum[slots + 1];
    signal input upperPotential[slots + 1][n];
    signal input lowerPotential[slots + 1][n];
    signal input upperHub[slots][g];
    signal input lowerHub[slots][g];
    signal input lower;
    signal input upper;
    signal input summarySalt;

    profile === policy;
    component scope = Poseidon(4);
    scope.inputs[0] <== 204201;
    scope.inputs[1] <== session;
    scope.inputs[2] <== profile;
    scope.inputs[3] <== entry;

    component evidenceStart = Poseidon(3);
    evidenceStart.inputs[0] <== 204202;
    evidenceStart.inputs[1] <== scope.out;
    evidenceStart.inputs[2] <== evidenceSalt;

    component chain[slots];
    component layer[slots];
    component pMax[slots + 1];
    component pMin[slots + 1];
    var allExits = 1;
    for (var v = 0; v < n; v++) {
        allExits *= exitFlags[v];
    }
    var totalMax = 0;
    var totalMin = 0;
    for (var i = 0; i <= slots; i++) {
        pMax[i] = Vertex(n, bits);
        pMin[i] = Vertex(n, bits);
        pMax[i].index <== maximum[i];
        pMin[i].index <== minimum[i];
    }
    for (var i = 0; i < slots; i++) {
        source[i] === open[i] * maximum[i];
        destination[i] === open[i] * maximum[i + 1];
        open[i] * (minimum[i] - maximum[i]) === 0;
        open[i] * (minimum[i + 1] - maximum[i + 1]) === 0;
        chain[i] = Poseidon(5);
        if (i == 0) {
            chain[i].inputs[0] <== evidenceStart.out;
        } else {
            chain[i].inputs[0] <== chain[i - 1].out;
        }
        chain[i].inputs[1] <== open[i];
        chain[i].inputs[2] <== source[i];
        chain[i].inputs[3] <== destination[i];
        chain[i].inputs[4] <== measured[i];

        layer[i] = PotentialLayer(n, bits, g, memberships, groupOf, targets, offsets,
                                  rLo[i], rHi[i], rExact[i], dLo[i], dHi[i],
                                  distanceBits, slackBits, allExits * (i == slots - 1));
        layer[i].isOpen <== open[i];
        layer[i].measuredDistance <== measured[i];
        layer[i].hubMax <== upperHub[i];
        layer[i].hubMin <== lowerHub[i];
        layer[i].fromMax <== pMax[i].select;
        layer[i].toMax <== pMax[i + 1].select;
        layer[i].fromMin <== pMin[i].select;
        layer[i].toMin <== pMin[i + 1].select;
        layer[i].originMax <== upperPotential[i];
        layer[i].originMin <== lowerPotential[i];
        layer[i].targetMax <== upperPotential[i + 1];
        layer[i].targetMin <== lowerPotential[i + 1];
        totalMax += layer[i].feeMax;
        totalMin += layer[i].feeMin;
    }
    chain[slots - 1].out === evidence;

    maximum[0] === entry;
    minimum[0] === entry;
    component entryMax = SelectSignal(n);
    component entryMin = SelectSignal(n);
    entryMax.select <== pMax[0].select;
    entryMin.select <== pMin[0].select;
    entryMax.values <== upperPotential[0];
    entryMin.values <== lowerPotential[0];
    entryMax.out === upper;
    entryMin.out === lower;

    var exitMax = 0;
    var exitMin = 0;
    for (var v = 0; v < n; v++) {
        if (exitFlags[v] == 1) {
            upperPotential[slots][v] === 0;
            lowerPotential[slots][v] === 0;
            exitMax += pMax[slots].select[v];
            exitMin += pMin[slots].select[v];
        }
    }
    exitMax === 1;
    exitMin === 1;
    totalMax === upper;
    totalMin === lower;
    component lowerRange = Num2Bits(amountBits);
    component upperRange = Num2Bits(amountBits);
    lowerRange.in <== lower;
    upperRange.in <== upper;

    component digest = Poseidon(6);
    digest.inputs[0] <== 204203;
    digest.inputs[1] <== scope.out;
    digest.inputs[2] <== evidence;
    digest.inputs[3] <== lower;
    digest.inputs[4] <== upper;
    digest.inputs[5] <== summarySalt;
    digest.out === summary;
}
