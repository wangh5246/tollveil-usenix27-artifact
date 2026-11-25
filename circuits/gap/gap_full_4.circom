pragma circom 2.1.9;
include "gap_update.circom";
component main {public [relation,sid,revision,policy,pkCommit,oldRoot,newRoot,deposit,oldRefund,deltaRefund]} = GapUpdate(0,24,0);
