pragma circom 2.0.0;

include "poseidon.circom";

// Self-contained ~100k-constraint Poseidon chain circuit for Gate G0.1/G0.2 calibration.
// 420 * 240 ~= 100,800 non-linear constraints (fits cleanly in pot17 = 131,072).
template PoseidonChain(N) {
    signal input seed;
    signal input salt;
    signal output digest;

    component h[N];
    for (var i = 0; i < N; i++) {
        h[i] = Poseidon(2);
        if (i == 0) {
            h[i].inputs[0] <== seed;
        } else {
            h[i].inputs[0] <== h[i - 1].out;
        }
        h[i].inputs[1] <== salt + i;
    }
    digest <== h[N - 1].out;
}

component main {public [salt]} = PoseidonChain(420);
