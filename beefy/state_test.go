package beefy_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	hug_encoding "github.com/dablelv/go-huge-util/encoding"
	beefy "github.com/octopus-network/beefy-go/beefy"
	trie_scale "github.com/octopus-network/trie-go/scale"
	sub "github.com/octopus-network/trie-go/substrate"
	trie_proof "github.com/octopus-network/trie-go/trie/proof"

	"github.com/stretchr/testify/require"
)

func TestDecodeReadProof(t *testing.T) {
	var readProof1 beefy.ReadProof
	readProofRespJson := `{"at":"0x7d1b45dcfa95b995551e39880335736f1f7a40f0fcbf399f7a62e6910561e792","proof":["0x802500801c4adc5ebbecb6ff1487ee17080d5125c7762c935041607962873b9217211df580dc464717fe3438ebb12469aa87aac2d84caf52ec37244c68438353f84958b750801a2ff24096295cfccf1adda80b8dfffe380b9f3b54d7a3cdb67864a4655e6296","0x80ffff80926b5710a46d0d8a877608f0e66e8bf2fa2bc8413d442628cd4def03e7d9dab48038bf81de8a1158a7b9f6567c11a88ea3d7615233bc6f4048af7d1c60821830528088a4e9e9369e65af97f4c9742b8989db22f7894117817efdbad5609e955c1b0d80158857e660f74042b1b2520bfc23b88b9370c929cee981e6ff759d22b1c6a9ef80a7916614651810f7beadbd750372cb4213e2a247563566b1777e47283602cc0e80d2d40061d9ede31ff6671feacf858666d7fea60fff3e8b762221db779a0428f180bf441943b5ae1e14896287fa28da999fa2791b02fc02aa67eaf894a7818a444a805b682132c52908705526057f73ab7fccab4af6d72a9805634dd8d3cc53f130d180c2d44d371e5fc1f50227d7491ad65ad049630361cefb4ab1844831237609f08380ab542a331c2e2107db577fc55a7ba5fe75ef85ccdf26de644e49bd1577062fb580b69e2f33f9b7704867209370683c4acc347729755ba62d99848ca74e96d9d1a8806b793079e7779d284eebd4b48ef914238d35047eae28d09b83468e7d0b09d4738049d573df8286d067c843345ce098fc1d0ccb454413670205d46f6d2fb4051d708001d049b75e16001b2928253a0827e37148c7702a69a8463a4a139fddea6a3230806bfdbbf0e0bedcb993b65c9cea1e929a56d78a3b7bc53d1b7ca6fc488e2295ee80183ad24af045b941b96eb7f07fe7987ccd655ef0a87543546348914a7b30fc3b","0x9ec365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20f29eaf2a86010000"]}`

	err := json.Unmarshal([]byte(readProofRespJson), &readProof1)

	require.NoError(t, err)
	// t.Log("readProof Unmarshal: ", readProof)
	t.Logf("readProof1 len: %d", len(readProof1.Proof))
	for _, p := range readProof1.Proof {
		t.Logf("readProof1.Proof: %s", p)
	}

	var readProof2 beefy.ReadProof
	readProofRespJson2 := `{"at":"0x65f92a9b259e4da0e436b29240ff3a6f342f83eacd129f9c9ca30797bbb6327c","proof":["0x80fff080f713131c16b3a818f1c817743e65eaef88e05bd4ca133bb0fa28ed05d85f821780ff8da33450d6b3edebd117ef90ab65c4c83ec9b7f1e9cc4fba8700cab1ebef7f80a0f1587562f24e2c68a9087e067e1aa2148c12f7856f69a7b118f0a87b0ec47280034e25e7254e9015172387bfa2bd297bd773f90f007f0106983ce6bac9485c7480eed757fbae435bec4f27b6d1ca6f157223567fc1728e596b7e0d77e1007023868024e3c4aa64ef9848a2a278deca772fde3b18d55fbec3166a571094849c29f3bc80aee3d4029b52c7be559d550480257d8346c0829f9111a9cf255b588f4d2f4b5b804d1b8741fc3785707843a0931bc3093464b18e16de342dbd514e9ebd6ef0e881802a0ed00e0b3c5491af5c6cb29b2dbc27dad5e81a29d7b32d453cca381e71fa3d8085ba31b59e40c53c4a00a0c0fbe984b967dbe21550d448db14547f644946cfeb80496a14ca32680365b5928d6f7e94baf41f58749aa854498fab5f2cb3d720073f80c7527be108ae40d5e01834646c343b649718312cc522c6cfdbb070fad525a1b4","0x9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20b501342b86010000"]}`
	err = json.Unmarshal([]byte(readProofRespJson2), &readProof2)
	require.NoError(t, err)
	t.Logf("readProof len: %d", len(readProof2.Proof))
	for _, p := range readProof2.Proof {
		t.Logf("readProof2.Proof: %s", p)
	}
}

func TestVerifyStateTrieLocal(t *testing.T) {
	t.Log("--- get parachain header from relay chain ---")
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	relayerBlockHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", relayerBlockHash)
	paraChainHeader, err := beefy.GetParachainHeader(relayApi, beefy.LOCAL_PARACHAIN_ID, relayerBlockHash)
	require.NoError(t, err)
	var decodeParachainHeader types.Header
	err = codec.Decode(paraChainHeader, &decodeParachainHeader)
	require.NoError(t, err)
	headerJson, err := hug_encoding.ToIndentJSON(decodeParachainHeader)
	require.NoError(t, err)
	t.Logf("paraChainHeader: %s", headerJson)
	t.Logf("paraBlockNumber: %d", decodeParachainHeader.Number)
	t.Logf("StateRoot: %#x", decodeParachainHeader.StateRoot)

	t.Log("--- get parachain timestamp and proof from parachain ---")
	paraChainApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_PARACHAIN_ENDPOINT)
	require.NoError(t, err)
	paraChainBlockHash, err := paraChainApi.RPC.Chain.GetBlockHash(uint64(decodeParachainHeader.Number))
	require.NoError(t, err)
	t.Logf("paraChainBlockHash: %#x", paraChainBlockHash)
	paraTimestampStoragekey := beefy.CreateStorageKeyPrefix("Timestamp", "Now")
	t.Logf("paraTimestampStoragekey: %#x", paraTimestampStoragekey)
	timestamp, err := beefy.GetTimestampValue(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	t.Logf("timestamp bytes: %+v", timestamp)
	var decodeTimestamp types.U64
	err = codec.Decode(timestamp, &decodeTimestamp)
	require.NoError(t, err)
	t.Logf("timestamp u64: %d", timestamp)
	time_str := time.UnixMilli(int64(decodeTimestamp))
	t.Logf("timestamp str: %s", time_str)

	timestampProof, err := beefy.GetTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	// t.Log("timestampProof: ", timestampProof)
	t.Logf("timestampProof len: %d", len(timestampProof.Proof))
	t.Logf("timestampProof at: %#x", timestampProof.At)
	// t.Logf("timestampProof: %+v", timestampProof)

	for _, proof := range timestampProof.Proof {
		t.Logf("timestampProof proof: %#x", proof)
	}

	proofs := make([][]byte, len(timestampProof.Proof))
	for _, proof := range timestampProof.Proof {
		proofs = append(proofs, proof[:])
	}

	trie, err := trie_proof.BuildTrie(proofs, decodeParachainHeader.StateRoot[:])
	t.Log("TRIE:\n", trie)
	require.NoError(t, err)

	value := trie.Get(paraTimestampStoragekey)
	t.Log("The Key Value:", value)
	var timestamp2 uint64
	err = trie_scale.Unmarshal(value, &timestamp2)
	if err != nil {
		panic(err)
	}
	t.Logf("timestamp: %d\n", timestamp2)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str2 := time.UnixMilli(int64(timestamp2))
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("timestamp: %s\n", time_str2)
}

func TestVerifyStateTrieRococo(t *testing.T) {
	t.Log("--- get parachain header from relay chain ---")
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.ROCOCO_ENDPOIN)
	require.NoError(t, err)
	relayerBlockHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", relayerBlockHash)
	paraChainHeader, err := beefy.GetParachainHeader(relayApi, beefy.ROCOCO_ROCKMIN_ID, relayerBlockHash)
	require.NoError(t, err)
	var decodeParachainHeader types.Header
	err = codec.Decode(paraChainHeader, &decodeParachainHeader)
	require.NoError(t, err)
	headerJson, err := hug_encoding.ToIndentJSON(decodeParachainHeader)
	require.NoError(t, err)
	t.Logf("paraChainHeader: %s", headerJson)
	t.Logf("paraBlockNumber: %d", decodeParachainHeader.Number)
	t.Logf("StateRoot: %#x", decodeParachainHeader.StateRoot)

	t.Log("--- get parachain timestamp and proof from parachain ---")
	paraChainApi, err := gsrpc.NewSubstrateAPI(beefy.ROCOCO_ROCKMIN_ENDPOINT)
	require.NoError(t, err)
	paraChainBlockHash, err := paraChainApi.RPC.Chain.GetBlockHash(uint64(decodeParachainHeader.Number))
	require.NoError(t, err)
	t.Logf("paraChainBlockHash: %#x", paraChainBlockHash)
	paraTimestampStoragekey := beefy.CreateStorageKeyPrefix("Timestamp", "Now")
	t.Logf("paraTimestampStoragekey: %#x", paraTimestampStoragekey)
	timestamp, err := beefy.GetTimestampValue(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	t.Logf("timestamp bytes: %+v", timestamp)
	var decodeTimestamp types.U64
	err = codec.Decode(timestamp, &decodeTimestamp)
	require.NoError(t, err)
	t.Logf("timestamp u64: %d", timestamp)
	time_str := time.UnixMilli(int64(decodeTimestamp))
	t.Logf("timestamp str: %s", time_str)

	timestampProof, err := beefy.GetTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	// t.Log("timestampProof: ", timestampProof)
	t.Logf("timestampProof len: %d", len(timestampProof.Proof))
	t.Logf("timestampProof at: %#x", timestampProof.At)
	// t.Logf("timestampProof: %+v", timestampProof)

	for _, proof := range timestampProof.Proof {
		t.Logf("timestampProof proof: %#x", proof)
	}

	proofs := make([][]byte, len(timestampProof.Proof))
	for i, proof := range timestampProof.Proof {
		proofs[i] = proof
	}

	trie, err := trie_proof.BuildTrie(proofs, decodeParachainHeader.StateRoot[:])
	t.Log("TRIE:\n", trie)
	require.NoError(t, err)

	value := trie.Get(paraTimestampStoragekey)
	t.Log("The Key Value:", value)
	var timestamp2 uint64
	err = trie_scale.Unmarshal(value, &timestamp2)
	if err != nil {
		panic(err)
	}
	t.Logf("timestamp: %d\n", timestamp2)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str2 := time.UnixMilli(int64(timestamp2))
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("timestamp: %s\n", time_str2)

	// build parachain proof
	targetParaHeaderStateProof, err := beefy.GetParachainHeaderProof(relayApi, relayerBlockHash, beefy.ROCOCO_ROCKMIN_ID)
	require.NoError(t, err)
	// t.Logf("targetParaHeaderStateProof: %+v", targetParaHeaderStateProof)
	paraHeaderStateproofs := make([][]byte, len(targetParaHeaderStateProof.Proof))
	for i, proof := range targetParaHeaderStateProof.Proof {
		paraHeaderStateproofs[i] = proof[:]
		t.Logf("paraHeaderStateproof: %x", proof)
	}
	meta, err := relayApi.RPC.State.GetMetadataLatest()
	require.NoError(t, err)
	paraIdEncoded := make([]byte, 4)
	binary.LittleEndian.PutUint32(paraIdEncoded, beefy.ROCOCO_ROCKMIN_ID)
	targetParaHeaderKey, err := types.CreateStorageKey(meta, "Paras", "Heads", paraIdEncoded)
	require.NoError(t, err)
	t.Logf("targetParaHeaderKey: %#x", targetParaHeaderKey)

	// trie, err = trie_proof.BuildTrie(paraHeaderStateproofs, decodeParachainHeader.StateRoot[:])
	// t.Log("TRIE:\n", trie)
	// require.NoError(t, err)

	// value = trie.Get(targetParaHeaderKey)
	// t.Log("The Key Value:", value)

	marShalTargetParaHeader, err := trie_scale.Marshal(paraChainHeader)
	require.NoError(t, err)
	t.Logf("marShalTargetParaHeader: %#x", marShalTargetParaHeader)
	err = beefy.VerifyStateProof(paraHeaderStateproofs, decodeParachainHeader.StateRoot[:], targetParaHeaderKey, marShalTargetParaHeader)
	require.NoError(t, err)
	t.Log("beefy.VerifyStateProof(proof,root,key,value) result: True")
	// require.True(t, result)

}

func TestVerifyStateTriePolkadot(t *testing.T) {
	t.Log("--- get parachain header from relay chain ---")
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.POLKADOT_ENDPOINT)
	require.NoError(t, err)
	relayerBlockHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", relayerBlockHash)
	// get astar header
	paraChainHeader, err := beefy.GetParachainHeader(relayApi, beefy.POLKADOT_ASTAR_ID, relayerBlockHash)
	require.NoError(t, err)
	var decodeParachainHeader types.Header
	err = codec.Decode(paraChainHeader, &decodeParachainHeader)
	require.NoError(t, err)
	headerJson, err := hug_encoding.ToIndentJSON(decodeParachainHeader)
	require.NoError(t, err)
	t.Logf("astar paraChainHeader: %s", headerJson)
	t.Logf("astar paraBlockNumber: %d", decodeParachainHeader.Number)
	t.Logf("astar header StateRoot: %#x", decodeParachainHeader.StateRoot)

	t.Log("--- get parachain timestamp and proof from astar parachain ---")
	paraChainApi, err := gsrpc.NewSubstrateAPI(beefy.POLKADOT_ASTAR_ENDPOINT)
	require.NoError(t, err)
	paraChainBlockHash, err := paraChainApi.RPC.Chain.GetBlockHash(uint64(decodeParachainHeader.Number))
	require.NoError(t, err)
	t.Logf("astar paraChainBlockHash: %#x", paraChainBlockHash)
	paraTimestampStoragekey := beefy.CreateStorageKeyPrefix("Timestamp", "Now")
	t.Logf("astar paraTimestampStoragekey: %#x", paraTimestampStoragekey)
	timestamp, err := beefy.GetTimestampValue(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	t.Logf("timestamp bytes: %+v", timestamp)
	var decodeTimestamp types.U64
	err = codec.Decode(timestamp, &decodeTimestamp)
	require.NoError(t, err)
	t.Logf("timestamp u64: %d", timestamp)
	time_str := time.UnixMilli(int64(decodeTimestamp))
	t.Logf("timestamp str: %s", time_str)

	timestampProof, err := beefy.GetTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	// t.Log("timestampProof: ", timestampProof)
	t.Logf("astar timestampProof len: %d", len(timestampProof.Proof))
	t.Logf("astar timestampProof at: %#x", timestampProof.At)
	// t.Logf("timestampProof: %+v", timestampProof)

	for _, proof := range timestampProof.Proof {
		t.Logf("astar timestampProof proof: %#x", proof)
	}

	astarProofs := make([][]byte, len(timestampProof.Proof))
	for _, proof := range timestampProof.Proof {
		astarProofs = append(astarProofs, proof[:])
	}

	astarTrie, err := trie_proof.BuildTrie(astarProofs, decodeParachainHeader.StateRoot[:])
	t.Log("TRIE:\n", astarTrie)
	require.NoError(t, err)

	value := astarTrie.Get(paraTimestampStoragekey)
	t.Log("The Key Value:", value)
	var timestamp2 uint64
	err = trie_scale.Unmarshal(value, &timestamp2)
	if err != nil {
		panic(err)
	}
	t.Logf("astar timestamp from trie tree: %d\n", timestamp2)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str2 := time.UnixMilli(int64(timestamp2))
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("astar timestamp from trie tree: %s\n", time_str2)

	// get composable header
	paraChainHeader, err = beefy.GetParachainHeader(relayApi, beefy.POLKADOT_COMPOSABLE_ID, relayerBlockHash)
	require.NoError(t, err)
	// var decodeParachainHeader types.Header
	err = codec.Decode(paraChainHeader, &decodeParachainHeader)
	require.NoError(t, err)
	headerJson, err = hug_encoding.ToIndentJSON(decodeParachainHeader)
	require.NoError(t, err)
	t.Logf("composable paraChainHeader: %s", headerJson)
	t.Logf("composable paraBlockNumber: %d", decodeParachainHeader.Number)
	t.Logf("composable header StateRoot: %#x", decodeParachainHeader.StateRoot)

	t.Log("--- get parachain timestamp and proof from composable parachain ---")
	paraChainApi, err = gsrpc.NewSubstrateAPI(beefy.POLKADOT_COMPOSABLE_ENDPOINT)
	require.NoError(t, err)
	paraChainBlockHash, err = paraChainApi.RPC.Chain.GetBlockHash(uint64(decodeParachainHeader.Number))
	require.NoError(t, err)
	t.Logf("composable paraChainBlockHash: %#x", paraChainBlockHash)
	paraTimestampStoragekey = beefy.CreateStorageKeyPrefix("Timestamp", "Now")
	t.Logf("composable paraTimestampStoragekey: %#x", paraTimestampStoragekey)
	timestamp, err = beefy.GetTimestampValue(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	t.Logf("timestamp bytes: %+v", timestamp)
	var decodeTimestamp2 types.U64
	err = codec.Decode(timestamp, &decodeTimestamp2)
	require.NoError(t, err)
	t.Logf("timestamp u64: %d", decodeTimestamp2)
	time_str2 = time.UnixMilli(int64(decodeTimestamp2))
	t.Logf("timestamp str: %s", time_str2)

	timestampProof, err = beefy.GetTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	// t.Log("timestampProof: ", timestampProof)
	t.Logf("composable timestampProof len: %d", len(timestampProof.Proof))
	t.Logf("composable timestampProof at: %#x", timestampProof.At)
	// t.Logf("timestampProof: %+v", timestampProof)

	for _, proof := range timestampProof.Proof {
		t.Logf("astar timestampProof proof: %#x", proof)
	}

	composableProofs := make([][]byte, len(timestampProof.Proof))
	for _, proof := range timestampProof.Proof {
		composableProofs = append(composableProofs, proof[:])
	}

	composabelTrie, err := trie_proof.BuildTrie(composableProofs, decodeParachainHeader.StateRoot[:])
	t.Log("TRIE:\n", composabelTrie)
	require.NoError(t, err)

	value = composabelTrie.Get(paraTimestampStoragekey)
	t.Log("The Key Value:", value)
	// var timestamp2 uint64
	err = trie_scale.Unmarshal(value, &timestamp2)
	if err != nil {
		panic(err)
	}
	t.Logf("astar timestamp from trie tree: %d\n", timestamp2)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str2 = time.UnixMilli(int64(timestamp2))
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("astar timestamp from trie tree: %s\n", time_str2)
}

func TestVerifyStateProof(t *testing.T) {
	// var readProof beefy.ReadProof
	// readProofRespJson := `{"at":"0xf19227284452923186534ea157e5d0e62e14176534275260b10f8269617e791c","proof":["0x013c30372d74656e6465726d696e742d333031302d6772616e6470612d30000c69626304043108344f524445525f4f5244455245443c4f524445525f554e4f524445524544000000000000000000000000","0x3f1a0c54bc99cb21cf5bd5f95c85b24c20e030636f6e6e656374696f6e2d33f47a1f097e5729662167ad9354d17eff20f69d6b5119f922e78ee4a528b76aeb","0x80a81480375c24be9b1fd88c4d489f577417c8772fa470d345414b7c82aac1926178ebc780ad5851cca1c8561bdf0e31e0c971603d537b110177870d35366a3ee71d5bbea980a7503c09f2379bfd9e22f7f111b0fd0165f9ac4f25983d72b95a8ce0534b80dc8007fce94d98a0b496b1aea95bfc79d220263e3a5c1eb0a3ddb2e4593707e512ce80517736f059379ae47402cf9b5d9306d732b3a57362f23690da174c9ace2d1684","0x80ffff8015333c63a2b46e1f9b271a96791f3c56295d7d991df20543e1b438aa3748295f808fac0e6f5dea47dac0f39cc49e8e86377c31ebb27c54117833f1b050ab0920658061de59aa253c48cc44a4e95cacf3a166d4b23a54717b57ee4ef9e1e631a018be8016384c0a42bfdf5d5b285ef34b33a0bc018a92bfe28f4332aa51d1f014ab9c068018a6618c8534b842d1bcc5ede707b6ecd6b781a253abf4a6fd414af7877c2ba280ca9db1977ce5dcd89f6f4d08468be5c5f62e7fe8f58bc269ec36b98381b3f6f4803838079f6c7d5cdfdef838bf2405bd36062ad2c5705af68a4cc696f679b58aec805b682132c52908705526057f73ab7fccab4af6d72a9805634dd8d3cc53f130d180c2d44d371e5fc1f50227d7491ad65ad049630361cefb4ab1844831237609f083801b8e006833c9d3f3b3b7f205c3077bc4cd10ada503774a9e1337a9db941fe89780f3d3330c6eae84ccbd3a67dc94e0b29f81e0ce3d9a2d024b75825a7f33234d3b804b9297c556f50a8573efed63fbc150532b574b164da35d5b0141dc2c5651b24680ad3469b2f5cec9d87f9889b030c4960264efd7fc4c775accc707899dd9d494c7802fc33bfebf7ec7f674e75686bcbe6355e602c2325e2013e854db77a773319c9d806bfdbbf0e0bedcb993b65c9cea1e929a56d78a3b7bc53d1b7ca6fc488e2295ee80294ff245427f8450d7bb4a23ce67ac38272da3a89bdc0086d77a8d8ec7c65278","0x9eccf20369c0dddad82d1003523ac48ebd26685f0abcf51bde418a0e566b7a4b421f3bf22004000000000000008075af3be3798b8458d29a156c9f7882448eab2a13a1e1e130d989826ed3c98d7880e759306fe6540a882433a76afb8595e442d017a5b21d029ba3105ccd8745e14f505f0e7b9012096b41c4eb3aaf947f6ea42908000080a72ce6c4a1c15388fe0bcbc32f8c287e9314c53beee00e4738d7c2d771e65d04685f0dafda4121e19633eda07b25f80a645d2004000000000000008074a24db85c1f5dcbfa7e4859a2e5b925542d8817b32674087a0f1722db20927880e373891e14b5cb02fea91d83be9c11214016498f432fbaa3251a48bc8ac15d2e8019a943d9b96ad120fdefb3ea0ad16fdbe0af1519fc9dc41c59f337706265ab43","0x9f0f63635057f9af33e8e4c0809c9c34c52a008037087705cdd8dcff040ec55d26a3aa4ed03ca23a8db4ae76cac80a50609cd8e08008a64a1b3e844af45da26e49bb9e5e9b174a7d3651f9a1cb518794cd9fbce7ed80a28fdb9fe07dfa8f09b07ce9d6ec60d9ee0c69897af812e47672b7b27e8cc756"]}`

	// err := json.Unmarshal([]byte(readProofRespJson), &readProof)

	// require.NoError(t, err)
	// // t.Log("readProof Unmarshal: ", readProof)
	// // t.Logf("readProof len: %d", len(readProof.Proof))
	// // for _, p := range readProof.Proof {
	// // 	t.Logf("readProof.Proof: %s", p)
	// // }
	// var proofs [][]byte
	// for _, p := range readProof.Proof {
	// 	// var proof types.Bytes
	// 	proof, err := codec.HexDecodeString(p)
	// 	require.NoError(t, err)
	// 	proofs = append(proofs, proof)
	// }
	// t.Logf("proofs: %+v", proofs)

	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)

	// latestFinalizedHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	// require.NoError(t, err)
	blockHash, err := types.NewHashFromHexString("0x09415c1184d94bb168e26ee676c0dfaf9a1f83106d66abceff277887b982f0bd")
	// hex.DecodeString("f19227284452923186534ea157e5d0e62e14176534275260b10f8269617e791c")
	require.NoError(t, err)
	t.Logf("blockHash: %+v", blockHash)
	// 0x65ccf20369c0dddad82d1003523ac48e2f63635057f9af33e8e4c0809c9c34c51c54bc99cb21cf5bd5f95c85b24c20e030636f6e6e656374696f6e2d33
	storageKeys := []string{"0x65ccf20369c0dddad82d1003523ac48e2f63635057f9af33e8e4c0809c9c34c51c54bc99cb21cf5bd5f95c85b24c20e030636f6e6e656374696f6e2d33"}
	stateProof, err := beefy.GetStateProof(relayApi, blockHash, storageKeys)
	require.NoError(t, err)
	t.Logf("stateProof: %+v", stateProof)
	proofs := make([][]byte, len(stateProof.Proof))
	for i, proof := range stateProof.Proof {
		proofs[i] = proof
	}
	t.Logf("proofs: %+v", proofs)
	blochHeader, err := relayApi.RPC.Chain.GetHeader(blockHash)
	// endFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(endBlockNumber))
	require.NoError(t, err)
	t.Logf("blochHeader.Number: %+v", blochHeader.Number)
	t.Logf("blochHeader.StateRoot: %+v", blochHeader.StateRoot)
	trie, err := trie_proof.BuildTrie(proofs, blochHeader.StateRoot[:])
	t.Log("TRIE:\n", trie)
	require.NoError(t, err)

	// trie_proof.Verify(proofs, blochHeader.StateRoot[:], key, value)
}

func TestVerifyParachainStateProoflocal(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	relayerBlockHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)

	relaychainHeader, err := relayApi.RPC.Chain.GetHeader(relayerBlockHash)
	require.NoError(t, err)
	// var decodeRelaychainHeader types.Header
	// err = codec.Decode(relaychainHeader, &decodeRelaychainHeader)
	require.NoError(t, err)
	t.Logf("relayer BlockHash: %#x", relayerBlockHash)
	t.Logf("relayer Blocknumber: %d", relaychainHeader.Number)
	t.Logf("relayer Block header state root: %#x", relaychainHeader.StateRoot)
	t.Log("--- get parachain header from relay chain ---")

	paraChainHeader, err := beefy.GetParachainHeader(relayApi, beefy.LOCAL_PARACHAIN_ID, relayerBlockHash)
	require.NoError(t, err)
	t.Logf("paraChainHeader: %#x", paraChainHeader)

	var decodeParachainHeader types.Header
	err = codec.Decode(paraChainHeader, &decodeParachainHeader)
	require.NoError(t, err)
	// headerJson, err := hug_encoding.ToIndentJSON(decodeParachainHeader)
	// require.NoError(t, err)
	// t.Logf("paraChainHeader: %s", headerJson)
	t.Logf("paraChainHeader: %#x", paraChainHeader)
	t.Logf("parachain BlockNumber: %d", decodeParachainHeader.Number)
	// t.Logf("parachain header StateRoot: %x", decodeParachainHeader.StateRoot)
	// marShalParaHeader, err := trie_scale.Marshal(decodeParachainHeader)
	// require.NoError(t, err)
	// t.Logf("marShalParaHeader: %#x", marShalParaHeader)

	// build parachain proof
	targetParaHeaderStateProof, err := beefy.GetParachainHeaderProof(relayApi, relayerBlockHash, beefy.LOCAL_PARACHAIN_ID)
	require.NoError(t, err)
	// t.Logf("targetParaHeaderStateProof: %+v", targetParaHeaderStateProof)
	paraHeaderStateproofs := make([][]byte, len(targetParaHeaderStateProof.Proof))
	for i, proof := range targetParaHeaderStateProof.Proof {
		paraHeaderStateproofs[i] = proof[:]
		t.Logf("paraHeaderStateproof: %x", proof)
	}
	// t.Logf("paraHeaderStateproofs: %+v", paraHeaderStateproofs)

	meta, err := relayApi.RPC.State.GetMetadataLatest()
	require.NoError(t, err)
	paraIdEncoded := make([]byte, 4)
	binary.LittleEndian.PutUint32(paraIdEncoded, beefy.LOCAL_PARACHAIN_ID)
	targetParaHeaderKey, err := types.CreateStorageKey(meta, "Paras", "Heads", paraIdEncoded)
	require.NoError(t, err)
	t.Logf("targetParaHeaderKey: %#x", targetParaHeaderKey)

	// trie, err := trie_proof.BuildTrie(paraHeaderStateproofs, relaychainHeader.StateRoot[:])
	// t.Log("TRIE:\n", trie)
	// require.NoError(t, err)

	// value := trie.Get(targetParaHeaderKey)
	// t.Log("The Key Value:", value)

	marShalTargetParaHeader, err := trie_scale.Marshal(paraChainHeader)
	require.NoError(t, err)
	t.Logf("marShalTargetParaHeader: %#x", marShalTargetParaHeader)
	err = beefy.VerifyStateProof(paraHeaderStateproofs, decodeParachainHeader.StateRoot[:], targetParaHeaderKey, marShalTargetParaHeader)
	require.NoError(t, err)
	t.Log("beefy.VerifyStateProof(proof,root,key,value) result: True")

}

func TestVerifyParachainStateProof(t *testing.T) {

	stateRoot, err := hex.DecodeString("470a069fc4eec01e7a8aa0e55a5c75db2c495efebcf684fdada8f1c6c63290c0")
	require.NoError(t, err)

	// parachain id 2000 header storage key
	key, err := hex.DecodeString("cd710b30bd2eab0352ddcc26417aa1941b3c252fcb29d88eff4f3de5de4476c363f5a4efb16ffa83d0070000")
	require.NoError(t, err)

	// para header 
	paraHeader, err := hex.DecodeString("d90f400ff2253268a3025685f884dcc804d40871929998b083a9bf2cbee3c6cfed017f4d9b48dfc57905fae71b366a2078b6de4a580d1c9c7df8a7fed9bf7ac5e295ceed0096eaaae75144c0048093c959274f1ccd753d3db34d18138cec907cccfe080661757261207aa05c080000000005617572610101e6d19993d90d1646568c5089ed21d8265886fdeb2261d3169e7551b08eb74a7772983dbd6b0ebcf1287011500f1acf70522baf08623758820181dfc70c6a3589")
	require.NoError(t, err)
	
	//nolint:lll
	bytes1, err := hex.DecodeString("3f180b3c252fcb29d88eff4f3de5de4476c363f5a4efb16ffa83d00700008cb5961e430e84c78fd485ddc5f48734525bdb26d814b7f4953ff10f4974b174")

	require.NoError(t, err)

	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	// t.Log("N1:", n1)
	t.Logf("N1:%+v", n1)

	//nolint:lll
	//
	bytes2, err := hex.DecodeString("8004648031b60c9237ed343094831987f2bec10b211621255ad0b440cf161fa820d30db480f6f6801e4b41e2e6d8ec194dba122bfb9eb33feb2545ef5144cea79551f7cc528012cb74d5658cc044408815a1ce1104b4c5ca791dc0135e9074ad130d40fdf79d80eb2131e1e8e24de6f91fd32addc2c0b4db59dddda6bd17c69bfe57d3d87745ca")
	require.NoError(t, err)
	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	//nolint:lll
	bytes3, err := hex.DecodeString("80ffff806219f485445da4884feea1f09b933bc77eb34e96aa059fa4c9fc096aa7a113cb80e59d7b787f421c048a6324f9c62135f42ffd466345883a95aab01d63a7dd26ee80d9981a224a7cd55255464744e0938e1cf600a2825d0d119ce1e6ed36ab15050f805b0999d27a38ad533fe643d6756b71fa7e684599d748f7de04a14d848d1ebde1800c4a0d3ce7d2560fdeeb704e62ec81d7aea9d269d050c13a2871d3800b0c121c80f82b4e4186441431b121df8d97e51b0d1390a1018753801992aa23b78309e54280a8946a28c482ead765fc8319e70464359d263fcc70cf52acfc44a54765653a39805b682132c52908705526057f73ab7fccab4af6d72a9805634dd8d3cc53f130d180c2d44d371e5fc1f50227d7491ad65ad049630361cefb4ab1844831237609f083804f6fb4ba043bc584d1c8b1ae82fb9a103e9d2e8b3c3ec726302f36a058d6c3c6809c33081b8ee4a18031c53cbaa4719556a593d650d4f75a34084df024d74a963b8030f8ff439d3a5ecdbd2a6ce3b1577c59a737a91550024c6fed952ef2ccb3fb8980587e95370248f105507977d5adbaadcfc2f49bd26daaa477756d71cac6de9b52806635c9ab61ee8dcd74e50d485cb4ab08d0b7c3a7f383d09a92fd6f58795ed4de806bfdbbf0e0bedcb993b65c9cea1e929a56d78a3b7bc53d1b7ca6fc488e2295ee80e78a212a664df92a357f3820e250342cb40fbf60aaa71751a85941466790ee5a")
	require.NoError(t, err)
	n3, err := sub.Decode(bytes.NewReader(bytes3))
	require.NoError(t, err)
	_, _ = n3.CalculateMerkleValue()
	t.Log("N3:", n3)

	bytes4, err := hex.DecodeString("9e710b30bd2eab0352ddcc26417aa1945f4380699a53b51a9709a3a86039c49b5ef278e9fc244dae27e1a0380c91bff5b04885803284444dab27d8408f88b637143dcdde93648410c975c9dcf8ec580d7e8f3ec77c77081e0bfde17b36573208a06cb5cfba6b63f5a4efb16ffa83d0070000040280050fb9422cfb4cf5fa865879260a44dc24d432de97da9a960f34db22d74f70dd505f0e7b9012096b41c4eb3aaf947f6ea4290800004c5f03c716fb8fff3de61a883bb76adb34a20400805e290f2677915a695fb33533682c80c169044705b243c2e80e00f71aadf604b54c5f0f4993f016e2d2f8e5f43be7bb25948604008054c03fbb201074f300a4e963ab0db0fd10a34afe0b3b22db3ab063d724d2a23c")
	require.NoError(t, err)
	n4, err := sub.Decode(bytes.NewReader(bytes4))
	require.NoError(t, err)
	_, _ = n4.CalculateMerkleValue()
	t.Log("N4:", n4)

	bytes5, err := hex.DecodeString("e102d90f400ff2253268a3025685f884dcc804d40871929998b083a9bf2cbee3c6cfed017f4d9b48dfc57905fae71b366a2078b6de4a580d1c9c7df8a7fed9bf7ac5e295ceed0096eaaae75144c0048093c959274f1ccd753d3db34d18138cec907cccfe080661757261207aa05c080000000005617572610101e6d19993d90d1646568c5089ed21d8265886fdeb2261d3169e7551b08eb74a7772983dbd6b0ebcf1287011500f1acf70522baf08623758820181dfc70c6a3589")
	require.NoError(t, err)
	n5, err := sub.Decode(bytes.NewReader(bytes5))
	require.NoError(t, err)
	_, _ = n5.CalculateMerkleValue()
	t.Log("N5:", n5)

	proof := [][]byte{bytes2,bytes1,  bytes3, bytes4, bytes5}

	// trie, err := trie_proof.BuildTrie(proof, stateRoot)
	// // t.Log("TRIE:", trie)
	// require.NoError(t, err)
	// value := trie.Get(key)
	// t.Log("The Key Value:", value)
	
	marShalParaHeader, err := trie_scale.Marshal(paraHeader)
	require.NoError(t, err)
	t.Logf("marShalTargetParaHeader: %#x", marShalParaHeader)
	err = beefy.VerifyStateProof(proof, stateRoot, key, marShalParaHeader)
	require.NoError(t, err)
	t.Log("beefy.VerifyStateProof(proof,root,key,value) result: True")
}

func TestVerifyTimestampProof(t *testing.T) {

	root, err := hex.DecodeString("ca161f57c8750c688d960e34c2b8b266d19c2c73e2adaac11e1ed35c94dbf23c")
	require.NoError(t, err)
	// parachain timestamp now storage key
	key, err := hex.DecodeString("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("80fff0808a66c19052add13a202bcd73b546ae0cb70544f166c4a469672c666f0a5f9d8a800cc297947d2287bb135dd1d434c082985483e28375bd2cee3025d3aeb76db6ee807aa6ab9a98d0400161a42f305f48ede3d7e5740e8245fcb8c6075f0996e240a280a0a9b3999cbcb2eb77a14d7240aa6cbfb5cfaca94584c7e6e71eaf272eed608a8089c16f1aff9b898e11f1f6012b9052703cb720660f48e08148436c2443113e6b805b4738371e424400dc403d779709b63288cb996f6c93c71e16b58404a32fd22580ebd1b5941227c0f4c151b89bc8cb29969333dc9f9336ede69e976d3235f8674a804d1b8741fc3785707843a0931bc3093464b18e16de342dbd514e9ebd6ef0e881804a53dc3bb38034bc19079b4042b073f66cf6c1ed1372df7f7d5141f05d98953980e8cafbef50a072daa5de180d2be3869dcb1187f5fb62e391aa55d235ef772c388096e8d574d3a273253ff74339b5bba5300cada312379c7016eb2dae5ca08be21080aeaed65890962f2af644619b6b2dee231ff72882eda5b711e134f8b6bec16728")

	require.NoError(t, err)

	// Root branch with partial key b""
	// Full key is b""
	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	// t.Log("N1:", n1)
	t.Logf("N1:%+v", n1)
	// Branch 2 with partial key b"", child 0 of branch 3 below.
	// Full key is b""
	//nolint:lll
	//
	bytes2, err := hex.DecodeString("9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb206f8e49f487010000")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	// Branch 3 with partial key b"", child 15 of root branch
	// Full key is b""
	//nolint:lll
	// bytes3, err := hex.DecodeString("8005088076c66e2871b4fe037d112ebffb3bfc8bd83a4ec26047f58ee2df7be4e9ebe3d680c1638f702aaa71e4b78cc8538ecae03e827bb494cc54279606b201ec071a5e24806d2a1e6d5236e1e13c5a5c84831f5f5383f97eba32df6f9faf80e32cf2f129bc")
	// require.NoError(t, err)

	// n3, err := sub.Decode(bytes.NewReader(bytes3))
	// require.NoError(t, err)
	// _, _ = n3.CalculateMerkleValue()
	// t.Log("N3:", n3)

	proof := [][]byte{
		bytes1, bytes2,
	}

	trie, err := trie_proof.BuildTrie(proof, root)
	// t.Log("TRIE:", trie)
	require.NoError(t, err)

	value := trie.Get(key)
	t.Log("The Key Value:", value)
	var timestamp uint64
	err = trie_scale.Unmarshal(value, &timestamp)
	if err != nil {
		panic(err)
	}
	t.Logf("timestamp: %d\n", timestamp)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str := time.UnixMilli(int64(timestamp))
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("timestamp: %s\n", time_str)
	require.NotEmpty(t, value)
}

func TestVerifyTimestampProof2(t *testing.T) {
	// local parachain data
	//0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb
	key, err := hex.DecodeString("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
	require.NoError(t, err)
	//stateRoot: 0x7c92bb461dcf0fb1c39a640180cf632fefd0fb588d191847c33c362ad8f15ad2
	root, err := hex.DecodeString("7c92bb461dcf0fb1c39a640180cf632fefd0fb588d191847c33c362ad8f15ad2")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("80fff080f713131c16b3a818f1c817743e65eaef88e05bd4ca133bb0fa28ed05d85f821780116d21b0772daa8e692606929ed0cfb00183ac9e8075352a40753a518424fc8480012a70d52be9baa9dbf76a80985265789c6d758ffd76462ad5a0a7a007ac59898085b5d720ddd73d6f24476d942d921fb47a42c44b3f445e85f9046cab55105a888046453c7eb3cfb556c1dd7a5ec02f5f23a2ba6a5f7c4d0045b80d37034bb4f917808154bcbdd40b99943cfb275d3844c708fc020620993300ba56e50e61519819d280aee3d4029b52c7be559d550480257d8346c0829f9111a9cf255b588f4d2f4b5b804d1b8741fc3785707843a0931bc3093464b18e16de342dbd514e9ebd6ef0e881802a0ed00e0b3c5491af5c6cb29b2dbc27dad5e81a29d7b32d453cca381e71fa3d8085ba31b59e40c53c4a00a0c0fbe984b967dbe21550d448db14547f644946cfeb80496a14ca32680365b5928d6f7e94baf41f58749aa854498fab5f2cb3d720073f808a99999ba548f3bed18ed7705ccbfb5aa94c47932c6c0b13d03e6a13f7de99bc")

	require.NoError(t, err)

	// Root branch with partial key b""
	// Full key is b""
	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	// t.Log("N1:", n1)
	t.Logf("N1:%+v", n1)
	// Branch 2 with partial key b"", child 0 of branch 3 below.
	// Full key is b""
	//nolint:lll
	//
	bytes2, err := hex.DecodeString("9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb209374ff2a86010000")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	proof := [][]byte{
		bytes1, bytes2,
	}

	trie, err := trie_proof.BuildTrie(proof, root)
	// t.Log("TRIE:", trie)
	require.NoError(t, err)

	value := trie.Get(key)
	t.Log("The Key Value:", value)
	var timestamp uint64
	err = trie_scale.Unmarshal(value, &timestamp)
	if err != nil {
		panic(err)
	}
	t.Logf("timestamp: %d\n", timestamp)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str := time.UnixMilli(int64(timestamp))
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("timestamp: %s\n", time_str)

	require.NotEmpty(t, value)
}

func TestVerifyTimestampProof3(t *testing.T) {
	// local parachain data
	//0xf0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb

	key, err := hex.DecodeString("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
	require.NoError(t, err)
	//stateRoot: 0x7c92bb461dcf0fb1c39a640180cf632fefd0fb588d191847c33c362ad8f15ad2
	root, err := hex.DecodeString("7c92bb461dcf0fb1c39a640180cf632fefd0fb588d191847c33c362ad8f15ad2")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("80fff080f713131c16b3a818f1c817743e65eaef88e05bd4ca133bb0fa28ed05d85f821780116d21b0772daa8e692606929ed0cfb00183ac9e8075352a40753a518424fc8480012a70d52be9baa9dbf76a80985265789c6d758ffd76462ad5a0a7a007ac59898085b5d720ddd73d6f24476d942d921fb47a42c44b3f445e85f9046cab55105a888046453c7eb3cfb556c1dd7a5ec02f5f23a2ba6a5f7c4d0045b80d37034bb4f917808154bcbdd40b99943cfb275d3844c708fc020620993300ba56e50e61519819d280aee3d4029b52c7be559d550480257d8346c0829f9111a9cf255b588f4d2f4b5b804d1b8741fc3785707843a0931bc3093464b18e16de342dbd514e9ebd6ef0e881802a0ed00e0b3c5491af5c6cb29b2dbc27dad5e81a29d7b32d453cca381e71fa3d8085ba31b59e40c53c4a00a0c0fbe984b967dbe21550d448db14547f644946cfeb80496a14ca32680365b5928d6f7e94baf41f58749aa854498fab5f2cb3d720073f808a99999ba548f3bed18ed7705ccbfb5aa94c47932c6c0b13d03e6a13f7de99bc")

	require.NoError(t, err)

	// Root branch with partial key b""
	// Full key is b""
	n1, err := sub.Decode(bytes.NewReader(bytes1))
	require.NoError(t, err)
	_, _ = n1.CalculateMerkleValue()
	// t.Log("N1:", n1)
	t.Logf("N1:%+v", n1)
	// Branch 2 with partial key b"", child 0 of branch 3 below.
	// Full key is b""
	//nolint:lll
	//
	bytes2, err := hex.DecodeString("9f00c365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb209374ff2a86010000")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	proof := [][]byte{
		bytes1, bytes2,
	}
	var timestamp uint64 = 1675758630035
	value, err := trie_scale.Marshal(timestamp)
	require.NoError(t, err)
	err = beefy.VerifyStateProof(proof, root, key, value)
	require.NoError(t, err)
	t.Log("beefy.VerifyStateProof(proof,root,key,value) result: True")
	// require.True(t, result)

}

// get parachain header state root from relaychain,
// and use that state root to verify proof from parachian
func TestVerifyTimestampLocal(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	relayerBlockHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Log("--- get parachain header from relay chain ---")
	t.Logf("relayerBlockHash: %#x", relayerBlockHash)
	paraChainHeader, err := beefy.GetParachainHeader(relayApi, beefy.LOCAL_PARACHAIN_ID, relayerBlockHash)
	require.NoError(t, err)
	var decodeParachainHeader types.Header
	err = codec.Decode(paraChainHeader, &decodeParachainHeader)
	require.NoError(t, err)
	// headerJson, err := hug_encoding.ToIndentJSON(decodeParachainHeader)
	// require.NoError(t, err)
	// t.Logf("paraChainHeader: %s", headerJson)

	t.Log("--- get parachain timestamp and proof from parachain ---")
	paraChainApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_PARACHAIN_ENDPOINT)
	require.NoError(t, err)
	paraChainBlockHash, err := paraChainApi.RPC.Chain.GetBlockHash(uint64(decodeParachainHeader.Number))
	require.NoError(t, err)
	t.Logf("parachainBlockNumber: %d", decodeParachainHeader.Number)
	t.Logf("parachainBlockHash: %#x", paraChainBlockHash)
	t.Logf("StateRoot: %#x", decodeParachainHeader.StateRoot)
	paraTimestampStoragekey := beefy.CreateStorageKeyPrefix("Timestamp", "Now")
	t.Logf("paraTimestampStoragekey: %#x", paraTimestampStoragekey)
	timestamp, err := beefy.GetTimestampValue(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	t.Logf("timestamp bytes: %+v", timestamp)
	var decodeTimestamp types.U64
	err = codec.Decode(timestamp, &decodeTimestamp)
	require.NoError(t, err)
	t.Logf("timestamp u64: %d", decodeTimestamp)
	time_str := time.UnixMilli(int64(decodeTimestamp))
	t.Logf("timestamp str: %s", time_str)

	timestampProof, err := beefy.GetTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	// t.Log("timestampProof: ", timestampProof)
	t.Logf("timestampProof len: %d", len(timestampProof.Proof))
	t.Logf("timestampProof at: %#x", timestampProof.At)

	proofs := make([][]byte, len(timestampProof.Proof))
	for i, proof := range timestampProof.Proof {
		t.Logf("timestampProof proof: %#x", proof)
		proofs[i] = proof
	}
	// t.Logf("timestampProof proofs: %+v", proofs)

	trie, err := trie_proof.BuildTrie(proofs, decodeParachainHeader.StateRoot[:])
	t.Log("TRIE:\n", trie)
	require.NoError(t, err)

	value := trie.Get(paraTimestampStoragekey)
	t.Log("The Key Value:", value)
	var timestamp2 uint64
	err = trie_scale.Unmarshal(value, &timestamp2)
	if err != nil {
		panic(err)
	}
	t.Logf("timestamp: %d\n", timestamp2)
	// time_str := time.UnixMicro(int64(timestamp))
	time_str2 := time.UnixMilli(int64(timestamp2))
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("timestamp: %s\n", time_str2)

	//verify timestamp proof
	// value2, err := trie_scale.Marshal(timestamp)
	// require.NoError(t, err)

	err = beefy.VerifyStateProof(proofs, decodeParachainHeader.StateRoot[:], paraTimestampStoragekey, timestamp)
	require.NoError(t, err)
	t.Log("beefy.VerifyStateProof(proof,root,key,value) result: True")
	// require.True(t, result)

	t.Log("--- test: build and verify timestamp proof ---")
	timestampWithProof, err := beefy.BuildTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	t.Logf("beefy.BuildTimestamp(paraChainApi, paraChainBlockHash): %+v", timestampWithProof)
	// value3, err := trie_scale.Marshal(timestampWithProof.Value)
	require.NoError(t, err)
	err = beefy.VerifyStateProof(timestampWithProof.Proofs, decodeParachainHeader.StateRoot[:], timestampWithProof.Key, timestampWithProof.Value)
	require.NoError(t, err)
	t.Log("beefy.VerifyStateProof(timestampWithProof.Proofs, decodeParachainHeader.StateRoot[:], timestampWithProof.Key, timestampWithProof.Value) result: True")
	// require.True(t, ret)
}
