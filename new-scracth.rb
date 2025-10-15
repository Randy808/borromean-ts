33
decryptionKeys[0][1] ^ t.outs[0].rangeProof[1]
22
decryptionKeys[0][2] ^ t.outs[0].rangeProof[2]
82
decryptionKeys[0][2] ^ t.outs[0].rangeProof[3]
82
decryptionKeys[0][3] ^ t.outs[0].rangeProof[3]
104


decryptionKeys[0][3] ^ t.outs[0].rangeProof[3]


decryptionKeys[0][0] ^ t.outs[0].rangeProof[0] 
// should be:
//0x60
//0x30


(t.outs[0].rangeProof[846] ^ decryptionKeys[0][0]).toString(16)
// should be 25