pragma circom 2.1.9;
include "gap_close.circom";
component main {public [relation,sid,revision,policy,pkCommit,oldRoot,deposit,oldRefund,infraMask,charge,refund,certifiedDigest]} = GapClose(4,24,0);
