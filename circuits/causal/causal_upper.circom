pragma circom 2.1.9;

include "potential.circom";
include "checkpoint_at.circom";
include "eddsaposeidon.circom";

// A path crossing a short layer uses a 3-by-3 box. The other graph is
// the exact three-row partition (one main block and two self-loops).
template CausalUpper(n, slots, cellX, cellY, sink, rowEdges, rowOffsets, colEdges, colOffsets, cover,
                     rateExact, rateUpper, shortCap, longCap, widths, tag, rel) {
    signal input relTag;
    signal input sid;
    signal input revision;
    signal input profile;
    signal input entry;
    signal input pkCommit;
    signal input deposit;
    signal input infraredMask;
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
    signal input isLongGap[slots];
    signal input cap[slots];
    signal input sealed[slots];
    signal input opened[slots];
    signal input measured[slots];
    signal input leafSalt[slots];
    signal input maximum[slots+1];
    signal input phi[slots+1][n];
    signal input live[slots+1][n];
    signal input rowHub[slots-1][400];
    signal input rowLive[slots-1][400];
    signal input boxHub[slots-1][n];
    signal input cliqueHub[slots-1];
    signal input upper;

    assert(rel == 1 || rel == 2);
    relTag === rel;
    profile === tag;
    if (rel == 1) {
        infraredMask === 0;
        charge === 0;
    }
    if (rel == 2) {
        charge === upper;
        refundDelta === deposit - oldRefund - charge;
        nextState === 0;
    }

    component identity = Poseidon(5);
    identity.inputs[0] <== 205001;
    identity.inputs[1] <== sid;
    identity.inputs[2] <== profile;
    identity.inputs[3] <== entry;
    identity.inputs[4] <== pkCommit;
    component pk = Poseidon(3);
    pk.inputs[0] <== Ax;
    pk.inputs[1] <== Ay;
    pk.inputs[2] <== keySalt;
    pk.out === pkCommit;

    component prior = Poseidon(9);
    prior.inputs[0] <== 205102;
    prior.inputs[1] <== identity.out;
    prior.inputs[2] <== revision;
    prior.inputs[3] <== oldMask;
    prior.inputs[4] <== oldCount;
    prior.inputs[5] <== oldUpper;
    prior.inputs[6] <== oldRefund;
    prior.inputs[7] <== oldSalt;

    component revRange = Num2Bits(32);
    revRange.in <== revision + (2-rel);
    // The ledger sets the additional terminal-eligibility bit from its clock.
    component infra = Num2Bits(slots + (rel == 2));
    infra.in <== infraredMask;
    component priorBits = Num2Bits(slots);
    priorBits.in <== oldMask;

    component path[slots+1];
    signal pathX[slots+1];
    signal pathY[slots+1];
    signal inSink[slots+1];
    for (var i=0; i<=slots; i++) {
        path[i] = Vertex(n, 9);
        path[i].index <== maximum[i];
        var x=0;
        var y=0;
        var sinkSum=0;
        for (var u=0; u<n; u++) {
            x += path[i].select[u] * cellX[u];
            y += path[i].select[u] * cellY[u];
            sinkSum += path[i].select[u] * sink[u];
        }
        pathX[i] <== x;
        pathY[i] <== y;
        inSink[i] <== sinkSum;
    }
    maximum[0] === entry;

    component header = Poseidon(3);
    header.inputs[0] <== 205003;
    header.inputs[1] <== identity.out;
    header.inputs[2] <== slots;
    component checkpoint[slots];
    component leaf[slots];
    component capRange[slots];
    component capWithinTier[slots];
    component dWithinCap[slots];
    component dRange[slots];
    component xNear[slots];
    component yNear[slots];
    component pathPotential[slots];
    component openedSlack[slots];
    component xDominates[slots-1][rowEdges[0][0]];
    component yDominates[slots-1][colEdges[0][0]];
    component cliqueDominates[slots-1][cover[0]];

    signal valid[slots];
    signal excuse[slots];
    signal isShortUnopened[slots];
    signal isLongUnopened[slots];
    signal paidCap[slots];
    signal pathCost[slots];
    signal pathOpenFee[slots];
    signal selectOpen[slots][n];
    signal longRequired[slots][n];
    signal shortRequired[slots][n];
    signal hubValue[slots][n];
    signal pendingValue[slots][n];
    signal pathUpperAtSource[slots];
    var count=0;
    var mask=0;
    var openedCount=0;
    var total=0;

    for (var i=0; i<slots; i++) {
        past[i]*(past[i]-1) === 0;
        fault[i]*(fault[i]-1) === 0;
        fault[i]*(1-past[i]) === 0;
        if (i>0) {
            past[i]*(1-past[i-1]) === 0;
        }
        valid[i] <== past[i]-fault[i];
        opened[i]*(opened[i]-1) === 0;
        opened[i]*(1-valid[i]) === 0;
        priorBits.out[i]*(1-opened[i]) === 0;
        isLongGap[i]*(isLongGap[i]-1) === 0;
        (1-valid[i])*(1-isLongGap[i]) === 0;
        (1-valid[i])*(cap[i]-longCap) === 0;
        (1-valid[i])*sealed[i] === 0;
        excuse[i] <== fault[i]*infra.out[i];
        paidCap[i] <== (1-excuse[i])*cap[i];
        isShortUnopened[i] <== (1-opened[i])*(1-isLongGap[i]);
        isLongUnopened[i] <== (1-opened[i])*isLongGap[i];
        capRange[i] = Num2Bits(9);
        capRange[i].in <== cap[i];
        capWithinTier[i] = Num2Bits(9);
        capWithinTier[i].in <== shortCap+(longCap-shortCap)*isLongGap[i]-cap[i];
        dWithinCap[i] = Num2Bits(9);
        dWithinCap[i].in <== cap[i]-measured[i];
        (1-opened[i])*measured[i] === 0;
        dRange[i] = Num2Bits(9);
        dRange[i].in <== measured[i];

        leaf[i] = Poseidon(6);
        leaf[i].inputs[0] <== 205010+i;
        leaf[i].inputs[1] <== identity.out;
        leaf[i].inputs[2] <== maximum[i];
        leaf[i].inputs[3] <== maximum[i+1];
        leaf[i].inputs[4] <== measured[i];
        leaf[i].inputs[5] <== leafSalt[i];
        opened[i]*(leaf[i].out-sealed[i]) === 0;

        checkpoint[i] = Poseidon(6);
        if (i==0) {
            checkpoint[i].inputs[0] <== header.out;
        } else {
            checkpoint[i].inputs[0] <== checkpoint[i-1].out;
        }
        checkpoint[i].inputs[1] <== past[i];
        checkpoint[i].inputs[2] <== fault[i];
        checkpoint[i].inputs[3] <== isLongGap[i];
        checkpoint[i].inputs[4] <== cap[i];
        checkpoint[i].inputs[5] <== sealed[i];

        xNear[i] = Num2Bits(2);
        yNear[i] = Num2Bits(2);
        xNear[i].in <== (1-isLongGap[i])*(1+pathX[i+1]-pathX[i]);
        yNear[i].in <== (1-isLongGap[i])*(1+pathY[i+1]-pathY[i]);
        xNear[i].out[0]*xNear[i].out[1] === 0;
        yNear[i].out[0]*yNear[i].out[1] === 0;
        inSink[i]*(maximum[i+1]-maximum[i]) === 0;

        var exactRate=0;
        var upperRate=0;
        for (var u=0; u<n; u++) {
            exactRate += path[i].select[u]*rateExact[i][u];
            upperRate += path[i].select[u]*rateUpper[i][u];
        }
        pathOpenFee[i] <== measured[i]*exactRate;
        pathUpperAtSource[i] <== paidCap[i]*upperRate;
        pathCost[i] <== pathOpenFee[i]+(1-opened[i])*pathUpperAtSource[i];

        count += past[i];
        mask += opened[i]*(2**i);
        openedCount += opened[i];
        total += pathCost[i];

        // First X, then Y. On long layers a fixed cover of horizontal
        // intervals bounds every destination using the same X hubs.
        if (i < slots-1) {
            for (var e=1; e<=rowEdges[0][0]; e++) {
                xDominates[i][e-1] = BoundedSlack(widths[i]);
                xDominates[i][e-1].enable <== 1;
                xDominates[i][e-1].left <== rowHub[i][rowEdges[e][0]];
                xDominates[i][e-1].right <== phi[i+1][rowEdges[e][1]];
            }
            for (var e=1; e<=colEdges[0][0]; e++) {
                yDominates[i][e-1] = BoundedSlack(widths[i]);
                yDominates[i][e-1].enable <== 1;
                yDominates[i][e-1].left <== boxHub[i][colEdges[e][0]];
                yDominates[i][e-1].right <== rowHub[i][colEdges[e][1]];
            }
            for (var e=1; e<=cover[0]; e++) {
                cliqueDominates[i][e-1] = BoundedSlack(widths[i]);
                cliqueDominates[i][e-1].enable <== 1;
                cliqueDominates[i][e-1].left <== cliqueHub[i];
                cliqueDominates[i][e-1].right <== boxHub[i][cover[e]];
            }
        }

        var anyLive=0;
        for (var u=0; u<n; u++) {
            anyLive += live[i+1][u];
        }
        if (i<slots-1) {
            for (var h=0; h<400; h++) {
                rowLive[i][h]*(rowLive[i][h]-1) === 0;
                var horizontal=0;
                for (var j=rowOffsets[h]; j<rowOffsets[h+1]; j++) {
                    horizontal += live[i+1][rowEdges[j][1]];
                }
                (1-rowLive[i][h])*horizontal === 0;
                if (rowOffsets[h]==rowOffsets[h+1]) {
                    rowHub[i][h] === 0;
                    rowLive[i][h] === 0;
                }
            }
        }
        for (var u=0; u<n; u++) {
            selectOpen[i][u] <== opened[i]*path[i].select[u];
            var reach=0;
            var local=0;
            var wide=0;
            if (i < slots-1) {
                if (sink[u]==1) {
                    reach = live[i+1][u];
                    local = phi[i+1][u];
                    wide = phi[i+1][u];
                } else {
                    for (var j=colOffsets[u]; j<colOffsets[u+1]; j++) {
                        reach += rowLive[i][colEdges[j][1]];
                    }
                    local = boxHub[i][u];
                    wide = cliqueHub[i];
                }
            } else {
                reach=1;
            }
            shortRequired[i][u] <== isShortUnopened[i]*reach;
            if (i==slots-1 || sink[u]==1) {
                longRequired[i][u] <== isLongUnopened[i]*reach;
            } else {
                longRequired[i][u] <== isLongUnopened[i]*anyLive;
            }
            live[i][u]*(live[i][u]-1) === 0;
            if (i==slots-1) {
                (1-live[i][u])*(selectOpen[i][u]+1-opened[i]) === 0;
                hubValue[i][u] <== 0;
                pendingValue[i][u] <== paidCap[i]*rateUpper[i][u];
            } else {
                (1-live[i][u])*(selectOpen[i][u]+shortRequired[i][u]+longRequired[i][u]) === 0;
                hubValue[i][u] <== local+isLongGap[i]*(wide-local);
                pendingValue[i][u] <== live[i][u]*(hubValue[i][u]+paidCap[i]*rateUpper[i][u]);
            }
            (1-opened[i])*(phi[i][u]-pendingValue[i][u]) === 0;
        }
    }

    for (var u=0; u<n; u++) {
        phi[slots][u] === 0;
        live[slots][u] === 1;
    }
    for (var i=0; i<slots; i++) {
        pathPotential[i] = SelectSignal(n);
        for (var u=0; u<n; u++) {
            pathPotential[i].select[u] <== path[i].select[u];
            pathPotential[i].values[u] <== phi[i][u];
        }
    }
    for (var i=0; i<slots; i++) {
        openedSlack[i] = BoundedSlack(18);
        openedSlack[i].enable <== opened[i];
        openedSlack[i].left <== pathPotential[i].out;
        if (i+1<slots) {
            openedSlack[i].right <== pathPotential[i+1].out+pathOpenFee[i];
        } else {
            openedSlack[i].right <== pathOpenFee[i];
        }
    }
    pathPotential[0].out === upper;
    total === upper;

    component sig = EdDSAPoseidonVerifier();
    sig.enabled <== 1;
    sig.Ax <== Ax;
    sig.Ay <== Ay;
    sig.R8x <== R8x;
    sig.R8y <== R8y;
    sig.S <== S;
    sig.M <== checkpoint[slots-1].out;

    component previousCheckpoint = CheckpointAt(slots);
    previousCheckpoint.count <== oldCount;
    previousCheckpoint.chain[0] <== header.out;
    for (var j=0; j<slots; j++) {
        previousCheckpoint.chain[j+1] <== checkpoint[j].out;
    }
    prior.inputs[8] <== previousCheckpoint.digest;
    prior.out === prevState;

    component counts[3];
    counts[0] = Num2Bits(4);
    counts[0].in <== oldCount;
    counts[1] = Num2Bits(4);
    counts[1].in <== count-oldCount;
    if (rel==1) {
        var oldCountOpen=0;
        for (var i=0; i<slots; i++) {
            oldCountOpen+=priorBits.out[i];
        }
        counts[2] = Num2Bits(1);
        counts[2].in <== openedCount-oldCountOpen;
        component currentCheckpoint = CheckpointAt(slots);
        currentCheckpoint.count <== count;
        currentCheckpoint.chain[0] <== header.out;
        for (var j=0; j<slots; j++) {
            currentCheckpoint.chain[j+1] <== checkpoint[j].out;
        }
        component next = Poseidon(9);
        next.inputs[0] <== 205102;
        next.inputs[1] <== identity.out;
        next.inputs[2] <== revision+1;
        next.inputs[3] <== mask;
        next.inputs[4] <== count;
        next.inputs[5] <== upper;
        next.inputs[6] <== oldRefund+refundDelta;
        next.inputs[7] <== newSalt;
        next.inputs[8] <== currentCheckpoint.digest;
        next.out === nextState;
    } else {
        count === slots;
        infra.out[slots] * (slots-openedCount) === 0;
        counts[2] = Num2Bits(1);
        counts[2].in <== 0;
    }

    component amounts[7];
    amounts[0] = Num2Bits(32);
    amounts[0].in <== deposit;
    amounts[1] = Num2Bits(32);
    amounts[1].in <== oldRefund;
    amounts[2] = Num2Bits(32);
    amounts[2].in <== oldUpper;
    amounts[3] = Num2Bits(18);
    amounts[3].in <== upper;
    amounts[4] = Num2Bits(32);
    amounts[4].in <== oldUpper-upper;
    amounts[5] = Num2Bits(32);
    amounts[5].in <== refundDelta;
    amounts[6] = Num2Bits(32);
    amounts[6].in <== deposit-upper-oldRefund-refundDelta;
}
