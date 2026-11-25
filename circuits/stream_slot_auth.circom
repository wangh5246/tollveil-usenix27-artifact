pragma circom 2.0.0;

include "eddsaposeidon.circom";
include "poseidon.circom";
include "bitify.circom";
include "comparators.circom";

// TollVeil v15 Phase 1: Streaming single-slot OBU hardware authentication,
// private-slot pending-mask retirement, and monotone escrow accounting transition.
//
// Public inputs (10):
//   session_id, corridor_id, model_root, tariff_root, pk_obu_commit,
//   deposit_D, prev_state_commit, new_state_commit, delta_C, delta_R
// All coordinates (u_i, v_i, d_i), slot_idx, OBU key (Ax, Ay, pk_salt),
// EdDSA signature (R8x, R8y, S), and internal bounds (L, U) stay strictly private.
template StreamSlotAuth(N_SLOTS) {
    // Public inputs
    signal input session_id;
    signal input corridor_id;
    signal input model_root;
    signal input tariff_root;
    signal input pk_obu_commit;
    signal input deposit_D;
    signal input prev_state_commit;
    signal input new_state_commit;
    signal input delta_C;
    signal input delta_R;

    // Private OBU key & signature inputs
    signal input Ax;
    signal input Ay;
    signal input pk_salt;
    signal input R8x;
    signal input R8y;
    signal input S;

    // Private single-slot measurement (discarded after this proof)
    signal input slot_idx;
    signal input u_i;
    signal input v_i;
    signal input d_i;

    // Private state opening (predecessor & successor)
    signal input prev_pending_mask;
    signal input prev_L;
    signal input prev_U;
    signal input prev_C;
    signal input prev_R;
    signal input prev_salt;

    signal input new_pending_mask;
    signal input new_L;
    signal input new_U;
    signal input new_salt;

    // 1. Open rerandomized OBU hardware public key commitment
    component pkHash = Poseidon(3);
    pkHash.inputs[0] <== Ax;
    pkHash.inputs[1] <== Ay;
    pkHash.inputs[2] <== pk_salt;
    pkHash.out === pk_obu_commit;

    // 2. Authenticate single streaming slot measurement under DOMAIN_SLOT=1001, STATUS_VALID=1
    component msgHash = Poseidon(7);
    msgHash.inputs[0] <== 1001;
    msgHash.inputs[1] <== session_id;
    msgHash.inputs[2] <== slot_idx;
    msgHash.inputs[3] <== u_i;
    msgHash.inputs[4] <== v_i;
    msgHash.inputs[5] <== d_i;
    msgHash.inputs[6] <== 1;

    component sigVer = EdDSAPoseidonVerifier();
    sigVer.enabled <== 1;
    sigVer.Ax <== Ax;
    sigVer.Ay <== Ay;
    sigVer.R8x <== R8x;
    sigVer.R8y <== R8y;
    sigVer.S <== S;
    sigVer.M <== msgHash.out;

    // 3. Verify predecessor state commitment
    component prevCommit = Poseidon(8);
    prevCommit.inputs[0] <== session_id;
    prevCommit.inputs[1] <== corridor_id;
    prevCommit.inputs[2] <== prev_pending_mask;
    prevCommit.inputs[3] <== prev_L;
    prevCommit.inputs[4] <== prev_U;
    prevCommit.inputs[5] <== prev_C;
    prevCommit.inputs[6] <== prev_R;
    prevCommit.inputs[7] <== prev_salt;
    prevCommit.out === prev_state_commit;

    // 4. Out-of-order single-slot retirement without revealing slot_idx
    component prevBits = Num2Bits(N_SLOTS);
    prevBits.in <== prev_pending_mask;
    component newBits = Num2Bits(N_SLOTS);
    newBits.in <== new_pending_mask;

    component isSlot[N_SLOTS];
    signal selSum[N_SLOTS + 1];
    selSum[0] <== 0;
    for (var j = 0; j < N_SLOTS; j++) {
        isSlot[j] = IsEqual();
        isSlot[j].in[0] <== slot_idx;
        isSlot[j].in[1] <== j;
        // If selected, bit j MUST have been pending (1) -> prevents double opening
        isSlot[j].out * (1 - prevBits.out[j]) === 0;
        // Exact bit flip: bit slot_idx transitions 1 -> 0, all others preserved
        newBits.out[j] === prevBits.out[j] - isSlot[j].out;
        selSum[j + 1] <== selSum[j] + isSlot[j].out;
    }
    // Enforce 0 <= slot_idx < N_SLOTS
    selSum[N_SLOTS] === 1;

    // 5. Monotone bounds, non-negative deltas, and solvency conservation
    signal new_C;
    signal new_R;
    new_C <== prev_C + delta_C;
    new_R <== prev_R + delta_R;

    // Range-check non-negativity (32-bit unsigned integer units)
    component rc_dC = Num2Bits(32);
    rc_dC.in <== delta_C;
    component rc_dR = Num2Bits(32);
    rc_dR.in <== delta_R;
    component rc_L_mono = Num2Bits(32);
    rc_L_mono.in <== new_L - prev_L;
    component rc_U_mono = Num2Bits(32);
    rc_U_mono.in <== prev_U - new_U;
    component rc_LU_order = Num2Bits(32);
    rc_LU_order.in <== new_U - new_L;
    component rc_C_safe = Num2Bits(32);
    rc_C_safe.in <== new_L - new_C;
    component rc_R_safe = Num2Bits(32);
    rc_R_safe.in <== (deposit_D - new_U) - new_R;

    // 6. Bind model_root and tariff_root into an explicit quadratic check so public inputs remain active
    signal policyBind;
    policyBind <== model_root * tariff_root;

    // 7. Verify successor state commitment
    component newCommit = Poseidon(8);
    newCommit.inputs[0] <== session_id;
    newCommit.inputs[1] <== corridor_id;
    newCommit.inputs[2] <== new_pending_mask;
    newCommit.inputs[3] <== new_L;
    newCommit.inputs[4] <== new_U;
    newCommit.inputs[5] <== new_C;
    newCommit.inputs[6] <== new_R;
    newCommit.inputs[7] <== new_salt;
    newCommit.out === new_state_commit;
}

component main {public [
    session_id,
    corridor_id,
    model_root,
    tariff_root,
    pk_obu_commit,
    deposit_D,
    prev_state_commit,
    new_state_commit,
    delta_C,
    delta_R
]} = StreamSlotAuth(8);
