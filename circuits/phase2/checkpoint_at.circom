pragma circom 2.1.9;

include "potential.circom";

// Bind the checkpoint at the certified count to the private state opening.
template CheckpointAt(slots) {
    signal input count;
    signal input chain[slots+1];
    signal output digest;
    component index = Vertex(slots+1, 4);
    index.index <== count;
    component select = SelectSignal(slots+1);
    for (var i=0; i<=slots; i++) {
        select.select[i] <== index.select[i];
        select.values[i] <== chain[i];
    }
    digest <== select.out;
}
