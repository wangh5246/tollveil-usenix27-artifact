pragma circom 2.1.9;

include "gap_update.circom";

template PinnedClose(n) {
    signal input flags[4];
    signal input origin[4];
    signal input target[4];
    signal input waived[4];
    signal input upper;
    signal output charge;
    signal output totalMissing;
    signal output credits[4];

    var opens=0;
    component live = Num2Bits(1);
    for (var i=0; i<4; i++) {
        opens += flags[i];
    }
    live.in <== opens-3;

    signal route[5];
    route[0] <== 0;
    route[4] <== 0;
    for (var i=1; i<4; i++) {
        route[i] <== target[i-1]+flags[i]*(origin[i]-target[i-1]);
    }
    component locator[5];
    for (var i=0; i<5; i++) {
        locator[i] = Vertex(n,5);
        locator[i].index <== route[i];
    }
    signal row[4][n];
    signal rowsSelected[4][n];
    signal edgeAmount[4];
    signal deducted[4];
    var whole=0;
    var discount=0;
    var miss=0;
    for (var i=0; i<4; i++) {
        flags[i]*(route[i]-origin[i]) === 0;
        flags[i]*(route[i+1]-target[i]) === 0;
        waived[i]*flags[i] === 0;
        var amount=0;
        for (var u=0; u<n; u++) {
            var knownFee=0;
            for (var v=0; v<n; v++) {
                knownFee += locator[i+1].select[v]*edgeFee(i,u,v);
            }
            row[i][u] <== knownFee;
            rowsSelected[i][u] <== locator[i].select[u]*row[i][u];
            amount += rowsSelected[i][u];
        }
        edgeAmount[i] <== amount;
        credits[i] <== (1-flags[i])*edgeAmount[i];
        deducted[i] <== waived[i]*credits[i];
        miss += credits[i];
        whole += edgeAmount[i];
        discount += deducted[i];
    }
    whole === upper;
    totalMissing <== miss;
    charge <== whole-discount;
}

template CloseDigest() {
    signal input sid;
    signal input revision;
    signal input policy;
    signal input before;
    signal input pkCommit;
    signal input deposit;
    signal input returned;
    signal input infra;
    signal input charge;
    signal input salt;
    signal output digest;
    component tag = Poseidon(11);
    tag.inputs[0] <== 205208;
    tag.inputs[1] <== sid;
    tag.inputs[2] <== revision;
    tag.inputs[3] <== policy;
    tag.inputs[4] <== before;
    tag.inputs[5] <== pkCommit;
    tag.inputs[6] <== deposit;
    tag.inputs[7] <== returned;
    tag.inputs[8] <== infra;
    tag.inputs[9] <== charge;
    tag.inputs[10] <== salt;
    digest <== tag.out;
}

template GapClose(gaps,n,arm) {
    signal input relation;
    signal input sid;
    signal input revision;
    signal input policy;
    signal input pkCommit;
    signal input oldRoot;
    signal input deposit;
    signal input oldRefund;
    signal input infraMask;
    signal input charge;
    signal input refund;
    signal input certifiedDigest;
    signal input salt;
    signal input faultMask[(arm!=0)];
    signal input Ax[(arm!=0)];
    signal input Ay[(arm!=0)];
    signal input pkSalt[(arm!=0)];
    signal input R8x[(arm!=0)];
    signal input R8y[(arm!=0)];
    signal input S[(arm!=0)];
    signal input oldSalt[gaps*(arm!=0)];
    signal input oldMask[gaps*(arm!=0)];
    signal input priorOrigin[gaps*(arm!=0)][4];
    signal input priorTarget[gaps*(arm!=0)][4];
    signal input priorUpper[gaps*(arm!=0)];

    relation === 205210+arm;
    policy === 205300+gaps;
    component digest = CloseDigest();
    digest.sid <== sid;
    digest.revision <== revision;
    digest.policy <== policy;
    digest.before <== oldRoot;
    digest.pkCommit <== pkCommit;
    digest.deposit <== deposit;
    digest.returned <== oldRefund;
    digest.infra <== infraMask;
    digest.charge <== charge;
    digest.salt <== salt;
    digest.digest === certifiedDigest;

    component widths[4];
    for (var i=0; i<4; i++) {
        widths[i] = Num2Bits(16);
    }
    widths[0].in <== deposit;
    widths[1].in <== oldRefund;
    widths[2].in <== charge;
    widths[3].in <== refund;
    deposit === oldRefund+charge+refund;
    component rev = Num2Bits(32);
    rev.in <== revision+1;
    component infra = Num2Bits(4*gaps);
    infra.in <== infraMask;

    // Arm 0 is valid only against a digest already certified by one
    // of the two authoritative relations below for the same scope.
    if (arm!=0) {

        component key = Poseidon(3);
        key.inputs[0] <== Ax[0];
        key.inputs[1] <== Ay[0];
        key.inputs[2] <== pkSalt[0];
        key.out === pkCommit;
        component fault = Num2Bits(4*gaps);
        fault.in <== faultMask[0];
        component signed = Poseidon(5);
        signed.inputs[0] <== 205209;
        signed.inputs[1] <== sid;
        signed.inputs[2] <== revision;
        signed.inputs[3] <== policy;
        signed.inputs[4] <== faultMask[0];
        component authentic = EdDSAPoseidonVerifier();
        authentic.enabled <== 1;
        authentic.Ax <== Ax[0];
        authentic.Ay <== Ay[0];
        authentic.R8x <== R8x[0];
        authentic.R8y <== R8y[0];
        authentic.S <== S[0];
        authentic.M <== signed.out;

        signal hd[2*gaps-1];
        signal amounts[2*gaps-1];
        component leaf[gaps];
        component nodes[gaps-1];
        component opened[gaps];
        component pinnedSolver[gaps];
        component rawSolver[gaps];
        signal effective[gaps][4];
        var total=0;
        for (var j=0; j<gaps; j++) {
            opened[j] = Num2Bits(4);
            opened[j].in <== oldMask[j];
            leaf[j] = GapEvidence();
            leaf[j].sid <== sid;
            leaf[j].index <== j;
            leaf[j].salt <== oldSalt[j];
            leaf[j].upper <== priorUpper[j];
            leaf[j].flags <== opened[j].out;
            leaf[j].origin <== priorOrigin[j];
            leaf[j].target <== priorTarget[j];
            hd[gaps-1+j] <== leaf[j].digest;
            amounts[gaps-1+j] <== priorUpper[j];
            for (var i=0; i<4; i++) {
                fault.out[4*j+i]*opened[j].out[i] === 0;
                effective[j][i] <== fault.out[4*j+i]*infra.out[4*j+i];
            }
            if (arm==1) {
                pinnedSolver[j] = PinnedClose(n);
                pinnedSolver[j].flags <== opened[j].out;
                pinnedSolver[j].origin <== priorOrigin[j];
                pinnedSolver[j].target <== priorTarget[j];
                pinnedSolver[j].waived <== effective[j];
                pinnedSolver[j].upper <== priorUpper[j];
                total += pinnedSolver[j].charge;
            } else {
                rawSolver[j] = GapMaximum(n);
                rawSolver[j].open <== opened[j].out;
                rawSolver[j].origin <== priorOrigin[j];
                rawSolver[j].target <== priorTarget[j];
                rawSolver[j].excused <== effective[j];
                total += rawSolver[j].upper;
            }
        }
        for (var j=gaps-2; j>=0; j--) {
            nodes[j] = GapNode();
            nodes[j].lhs <== hd[2*j+1];
            nodes[j].rhs <== hd[2*j+2];
            nodes[j].lUpper <== amounts[2*j+1];
            nodes[j].rUpper <== amounts[2*j+2];
            hd[j] <== nodes[j].digest;
            amounts[j] <== nodes[j].upper;
        }
        total === charge;
        hd[0] === oldRoot;
        component solvent = Num2Bits(16);
        solvent.in <== deposit-oldRefund-amounts[0];
    }
}
