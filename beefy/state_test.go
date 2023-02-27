package beefy_test

import (
	"encoding/json"
	"testing"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	hug_encoding "github.com/dablelv/go-huge-util/encoding"
	beefy "github.com/octopus-network/beefy-go/beefy"
	trie_scale "github.com/octopus-network/trie-go/scale"
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
