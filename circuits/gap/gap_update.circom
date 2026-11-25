pragma circom 2.1.9;

include "potential.circom";
include "comparators.circom";
include "eddsaposeidon.circom";

function edgeFee(i,u,v) {
    return 1 + (13*u + 9*v + 7*i + 3*u*v) % 63;
}

template MaxChain(n) {
    signal input candidate[n];
    signal output result;
    signal prefix[n];
    component cmp[n-1];
    prefix[0] <== candidate[0];
    for (var v=1; v<n; v++) {
        cmp[v-1] = LessThan(9);
        cmp[v-1].in[0] <== prefix[v-1];
        cmp[v-1].in[1] <== candidate[v];
        prefix[v] <== prefix[v-1] + cmp[v-1].out * (candidate[v]-prefix[v-1]);
    }
    result <== prefix[n-1];
}

// Registered waypoints pin both ends to vertex zero. Every remaining
// feasible vertex in the complete candidate graph has a live suffix.
template GapMaximum(n) {
    signal input open[4];
    signal input origin[4];
    signal input target[4];
    signal input excused[4];
    signal output upper;

    signal phi[5][n];
    signal live[5][n];
    signal exactCost[4][n];
    signal exactChosen[4][n];
    signal openCost[4];
    signal suffixLive[4];
    component src[4];
    component dst[4];
    component anchoredValue[4];
    component anchoredLive[4];
    component pending[4][n];
    signal observedPair[4][n];
    signal openedValue[4][n];

    for (var v=0; v<n; v++) {
        phi[4][v] <== 0;
        live[4][v] <== (v==0);
    }
    for (var i=3; i>=0; i--) {
        open[i]*(open[i]-1) === 0;
        excused[i]*(excused[i]-1) === 0;
        open[i]*excused[i] === 0;
        src[i] = Vertex(n, 5);
        dst[i] = Vertex(n, 5);
        src[i].index <== origin[i];
        dst[i].index <== target[i];
        (1-open[i])*origin[i] === 0;
        (1-open[i])*target[i] === 0;
        anchoredValue[i] = SelectSignal(n);
        anchoredValue[i].select <== dst[i].select;
        anchoredValue[i].values <== phi[i+1];
        anchoredLive[i] = SelectSignal(n);
        anchoredLive[i].select <== dst[i].select;
        anchoredLive[i].values <== live[i+1];
        open[i]*(1-anchoredLive[i].out) === 0;
        var exact = 0;
        for (var u=0; u<n; u++) {
            var fromCost = 0;
            for (var v=0; v<n; v++) {
                fromCost += dst[i].select[v]*edgeFee(i,u,v);
            }
            exactCost[i][u] <== fromCost;
            exactChosen[i][u] <== src[i].select[u]*exactCost[i][u];
            exact += exactChosen[i][u];
        }
        openCost[i] <== anchoredValue[i].out + exact;
        for (var u=0; u<n; u++) {
            pending[i][u] = MaxChain(n);
            for (var v=0; v<n; v++) {
                pending[i][u].candidate[v] <== live[i+1][v] *
                    (phi[i+1][v]+(1-excused[i])*edgeFee(i,u,v));
            }
            observedPair[i][u] <== open[i]*src[i].select[u];
            live[i][u] <== 1-open[i]+observedPair[i][u];
            openedValue[i][u] <== observedPair[i][u]*openCost[i];
            phi[i][u] <== (1-open[i])*pending[i][u].result + openedValue[i][u];
        }
    }
    live[0][0] === 1;
    upper <== phi[0][0];
}

template GapEvidence() {
    signal input sid;
    signal input index;
    signal input salt;
    signal input flags[4];
    signal input origin[4];
    signal input target[4];
    signal input upper;
    signal output digest;
    component tag = Poseidon(4);
    tag.inputs[0] <== 205200;
    tag.inputs[1] <== sid;
    tag.inputs[2] <== index;
    tag.inputs[3] <== salt;
    component chain[4];
    for (var i=0; i<4; i++) {
        chain[i] = Poseidon(4);
        if (i==0) {
            chain[i].inputs[0] <== tag.out;
        } else {
            chain[i].inputs[0] <== chain[i-1].out;
        }
        chain[i].inputs[1] <== flags[i];
        chain[i].inputs[2] <== origin[i];
        chain[i].inputs[3] <== target[i];
    }
    component root = Poseidon(3);
    root.inputs[0] <== 205201;
    root.inputs[1] <== chain[3].out;
    root.inputs[2] <== upper;
    digest <== root.out;
}

template GapTransition(n) {
    signal input sid;
    signal input index;
    signal input oldSalt;
    signal input proposedSalt;
    signal input oldMask;
    signal input oldOrigin[4];
    signal input oldTarget[4];
    signal input oldUpper;
    signal input enable;
    signal input changedSlot[4];
    signal input newOrigin;
    signal input newTarget;
    signal output before;
    signal output after;
    signal output upper;
    component previous = Num2Bits(4);
    previous.in <== oldMask;
    component oldAmount = Num2Bits(8);
    oldAmount.in <== oldUpper;
    component oldLeaf = GapEvidence();
    oldLeaf.sid <== sid;
    oldLeaf.index <== index;
    oldLeaf.salt <== oldSalt;
    oldLeaf.upper <== oldUpper;
    oldLeaf.flags <== previous.out;
    oldLeaf.origin <== oldOrigin;
    oldLeaf.target <== oldTarget;

    component newLeaf = GapEvidence();
    component solver = GapMaximum(n);
    newLeaf.sid <== sid;
    newLeaf.index <== index;
    newLeaf.salt <== oldSalt+enable*(proposedSalt-oldSalt);
    signal changed[4];
    for (var i=0; i<4; i++) {
        changed[i] <== enable*changedSlot[i];
        changed[i]*previous.out[i] === 0;
        solver.open[i] <== previous.out[i]+changed[i];
        solver.origin[i] <== oldOrigin[i]+changed[i]*newOrigin;
        solver.target[i] <== oldTarget[i]+changed[i]*newTarget;
        solver.excused[i] <== 0;
        newLeaf.flags[i] <== previous.out[i]+changed[i];
        newLeaf.origin[i] <== oldOrigin[i]+changed[i]*newOrigin;
        newLeaf.target[i] <== oldTarget[i]+changed[i]*newTarget;
    }
    newLeaf.upper <== solver.upper;
    before <== oldLeaf.digest;
    after <== newLeaf.digest;
    upper <== solver.upper;
}

template GapNode() {
    signal input lhs;
    signal input lUpper;
    signal input rhs;
    signal input rUpper;
    signal output digest;
    signal output upper;
    component hash = Poseidon(5);
    hash.inputs[0] <== 205202;
    hash.inputs[1] <== lhs;
    hash.inputs[2] <== lUpper;
    hash.inputs[3] <== rhs;
    hash.inputs[4] <== rUpper;
    digest <== hash.out;
    upper <== lUpper+rUpper;
}

template GapUpdate(depth,n,local) {
    var totalGaps = 2**depth;
    var checkedGaps = totalGaps + local * (1-totalGaps);
    var policyValue = 205300 + totalGaps;
    signal input relation;
    signal input sid;
    signal input revision;
    signal input policy;
    signal input pkCommit;
    signal input oldRoot;
    signal input newRoot;
    signal input deposit;
    signal input oldRefund;
    signal input deltaRefund;

    signal input gapIndex;
    signal input slotIndex;
    signal input Ax;
    signal input Ay;
    signal input pkSalt;
    signal input R8x;
    signal input R8y;
    signal input S;
    signal input oldSalt[checkedGaps];
    signal input oldMask[checkedGaps];
    signal input priorOrigin[checkedGaps][4];
    signal input priorTarget[checkedGaps][4];
    signal input priorUpper[checkedGaps];
    signal input newSalt;
    signal input exactOrigin;
    signal input exactTarget;
    signal input siblingHash[local*depth];
    signal input siblingUpper[local*depth];

    relation === 205100+local;
    policy === policyValue;
    component rev = Num2Bits(32);
    rev.in <== revision+1;
    component key = Poseidon(3);
    key.inputs[0] <== Ax;
    key.inputs[1] <== Ay;
    key.inputs[2] <== pkSalt;
    key.out === pkCommit;

    component attestation = Poseidon(6);
    attestation.inputs[0] <== 205203;
    attestation.inputs[1] <== sid;
    attestation.inputs[2] <== policy;
    attestation.inputs[3] <== 4*gapIndex+slotIndex;
    attestation.inputs[4] <== exactOrigin;
    attestation.inputs[5] <== exactTarget;
    component signer = EdDSAPoseidonVerifier();
    signer.enabled <== 1;
    signer.Ax <== Ax;
    signer.Ay <== Ay;
    signer.R8x <== R8x;
    signer.R8y <== R8y;
    signer.S <== S;
    signer.M <== attestation.out;
    signal bit[depth];
    if (depth==0) {
        gapIndex === 0;
    } else {
        component group = Num2Bits(depth);
        group.in <== gapIndex;
        bit <== group.out;
    }

    component sel = Vertex(4,2);
    sel.index <== slotIndex;
    component leaf[checkedGaps];
    component active[checkedGaps];
    for (var j=0; j<checkedGaps; j++) {
        leaf[j] = GapTransition(n);
        leaf[j].sid <== sid;
        if (local==1) {
            active[j] = IsEqual();
            active[j].in[0] <== 0;
            active[j].in[1] <== 0;
            leaf[j].index <== gapIndex;
        } else {
            active[j] = IsEqual();
            active[j].in[0] <== gapIndex;
            active[j].in[1] <== j;
            leaf[j].index <== j;
        }
        leaf[j].enable <== active[j].out;
        leaf[j].oldSalt <== oldSalt[j];
        leaf[j].proposedSalt <== newSalt;
        leaf[j].oldMask <== oldMask[j];
        leaf[j].oldOrigin <== priorOrigin[j];
        leaf[j].oldTarget <== priorTarget[j];
        leaf[j].oldUpper <== priorUpper[j];
        leaf[j].changedSlot <== sel.select;
        leaf[j].newOrigin <== exactOrigin;
        leaf[j].newTarget <== exactTarget;
    }

    signal aggregateBefore;
    signal aggregateAfter;
    if (local==1) {
        component oldNodes[depth];
        component newNodes[depth];
        signal hdBefore[depth+1];
        signal hdAfter[depth+1];
        signal amountBefore[depth+1];
        signal amountAfter[depth+1];
        hdBefore[0] <== leaf[0].before;
        hdAfter[0] <== leaf[0].after;
        amountBefore[0] <== priorUpper[0];
        amountAfter[0] <== leaf[0].upper;
        component capSib[depth];
        for (var l=0; l<depth; l++) {
            capSib[l] = Num2Bits(16);
            capSib[l].in <== siblingUpper[l];
            oldNodes[l] = GapNode();
            newNodes[l] = GapNode();
            oldNodes[l].lhs <== hdBefore[l]+bit[l]*(siblingHash[l]-hdBefore[l]);
            oldNodes[l].rhs <== siblingHash[l]+bit[l]*(hdBefore[l]-siblingHash[l]);
            newNodes[l].lhs <== hdAfter[l]+bit[l]*(siblingHash[l]-hdAfter[l]);
            newNodes[l].rhs <== siblingHash[l]+bit[l]*(hdAfter[l]-siblingHash[l]);
            oldNodes[l].lUpper <== amountBefore[l]+bit[l]*(siblingUpper[l]-amountBefore[l]);
            oldNodes[l].rUpper <== siblingUpper[l]+bit[l]*(amountBefore[l]-siblingUpper[l]);
            newNodes[l].lUpper <== amountAfter[l]+bit[l]*(siblingUpper[l]-amountAfter[l]);
            newNodes[l].rUpper <== siblingUpper[l]+bit[l]*(amountAfter[l]-siblingUpper[l]);
            hdBefore[l+1] <== oldNodes[l].digest;
            hdAfter[l+1] <== newNodes[l].digest;
            amountBefore[l+1] <== oldNodes[l].upper;
            amountAfter[l+1] <== newNodes[l].upper;
        }
        oldRoot === hdBefore[depth];
        newRoot === hdAfter[depth];
        aggregateBefore <== amountBefore[depth];
        aggregateAfter <== amountAfter[depth];
    } else {
        component oldNodes[totalGaps-1];
        component newNodes[totalGaps-1];
        signal hdBefore[2*totalGaps-1];
        signal hdAfter[2*totalGaps-1];
        signal amountBefore[2*totalGaps-1];
        signal amountAfter[2*totalGaps-1];
        for (var j=0; j<totalGaps; j++) {
            var i=totalGaps-1+j;
            hdBefore[i] <== leaf[j].before;
            hdAfter[i] <== leaf[j].after;
            amountBefore[i] <== priorUpper[j];
            amountAfter[i] <== leaf[j].upper;
        }
        for (var i=totalGaps-2; i>=0; i--) {
            oldNodes[i] = GapNode();
            newNodes[i] = GapNode();
            oldNodes[i].lhs <== hdBefore[2*i+1];
            oldNodes[i].rhs <== hdBefore[2*i+2];
            newNodes[i].lhs <== hdAfter[2*i+1];
            newNodes[i].rhs <== hdAfter[2*i+2];
            oldNodes[i].lUpper <== amountBefore[2*i+1];
            oldNodes[i].rUpper <== amountBefore[2*i+2];
            newNodes[i].lUpper <== amountAfter[2*i+1];
            newNodes[i].rUpper <== amountAfter[2*i+2];
            hdBefore[i] <== oldNodes[i].digest;
            hdAfter[i] <== newNodes[i].digest;
            amountBefore[i] <== oldNodes[i].upper;
            amountAfter[i] <== newNodes[i].upper;
        }
        oldRoot === hdBefore[0];
        newRoot === hdAfter[0];
        aggregateBefore <== amountBefore[0];
        aggregateAfter <== amountAfter[0];
    }
    component amount[6];
    for (var i=0; i<6; i++) {
        amount[i] = Num2Bits(16);
    }
    amount[0].in <== deposit;
    amount[1].in <== oldRefund;
    amount[2].in <== deltaRefund;
    amount[3].in <== deposit-oldRefund-aggregateBefore;
    amount[4].in <== aggregateBefore-aggregateAfter;
    amount[5].in <== deposit-oldRefund-deltaRefund-aggregateAfter;
}
