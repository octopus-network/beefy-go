package beefy_test

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	hug_encoding "github.com/dablelv/go-huge-util/encoding"
	"github.com/octopus-network/beefy-go/beefy"
	trie_scale "github.com/octopus-network/trie-go/scale"
	sub "github.com/octopus-network/trie-go/substrate"
	trie_proof "github.com/octopus-network/trie-go/trie/proof"

	"github.com/stretchr/testify/require"
)

func TestVerifyTimestampProof(t *testing.T) {
	// composable parachain data
	key, err := hex.DecodeString("f0c365c3cf59d671eb72da0e7a4113c49f1f0515f462cdcf84e0f1d6045dfcbb")
	require.NoError(t, err)

	root, err := hex.DecodeString("dc4887669c2a6b3462e9557aa3105a66a02b6ec3b21784613de78c95dc3cbbe0")
	require.NoError(t, err)

	//nolint:lll
	bytes1, err := hex.DecodeString("80fffd8028b54b9a0a90d41b7941c43e6a0597d5914e3b62bdcb244851b9fc806c28ea2480d5ba6d50586692888b0c2f5b3c3fc345eb3a2405996f025ed37982ca396f5ed580bd281c12f20f06077bffd56b2f8b6431ee6c9fd11fed9c22db86cea849aeff2280afa1e1b5ce72ea1675e5e69be85e98fbfb660691a76fee9229f758a75315f2bc80aafc60caa3519d4b861e6b8da226266a15060e2071bba4184e194da61dfb208e809d3f6ae8f655009551de95ae1ef863f6771522fd5c0475a50ff53c5c8169b5888024a760a8f6c27928ae9e2fed9968bc5f6e17c3ae647398d8a615e5b2bb4b425f8085a0da830399f25fca4b653de654ffd3c92be39f3ae4f54e7c504961b5bd00cf80c2d44d371e5fc1f50227d7491ad65ad049630361cefb4ab1844831237609f08380c644938921d14ae611f3a90991af8b7f5bdb8fa361ee2c646c849bca90f491e6806e729ad43a591cd1321762582782bbe4ed193c6f583ec76013126f7f786e376280509bb016f2887d12137e73d26d7ddcd7f9c8ff458147cb9d309494655fe68de180009f8697d760fbe020564b07f407e6aad58ba9451b3d2d88b3ee03e12db7c47480952dcc0804e1120508a1753f1de4aa5b7481026a3320df8b48e918f0cecbaed3803360bf948fddc403d345064082e8393d7a1aad7a19081f6d02d94358f242b86c")

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
	bytes2, err := hex.DecodeString("9ec365c3cf59d671eb72da0e7a4113c41002505f0e7b9012096b41c4eb3aaf947f6ea429080000685f0f1f0515f462cdcf84e0f1d6045dfcbb20865c4a2b7f010000")
	require.NoError(t, err)

	n2, err := sub.Decode(bytes.NewReader(bytes2))
	require.NoError(t, err)
	_, _ = n2.CalculateMerkleValue()
	t.Log("N2:", n2)

	// Branch 3 with partial key b"", child 15 of root branch
	// Full key is b""
	//nolint:lll
	bytes3, err := hex.DecodeString("8005088076c66e2871b4fe037d112ebffb3bfc8bd83a4ec26047f58ee2df7be4e9ebe3d680c1638f702aaa71e4b78cc8538ecae03e827bb494cc54279606b201ec071a5e24806d2a1e6d5236e1e13c5a5c84831f5f5383f97eba32df6f9faf80e32cf2f129bc")
	require.NoError(t, err)

	n3, err := sub.Decode(bytes.NewReader(bytes3))
	require.NoError(t, err)
	_, _ = n3.CalculateMerkleValue()
	t.Log("N3:", n3)

	proof := [][]byte{
		bytes1, bytes2, bytes3,
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
	result, err := beefy.VerifyStateProof(proof, root, key, value)
	t.Log("beefy.VerifyStateProof(proof,root,key,value) result:", result)
	require.NoError(t, err)
	require.True(t, result)

}

func TestVerifyTimestampLocal(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	relayerBlockHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Log("--- get parachain header from relay chain ---")
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
	t.Logf("timestamp u64: %d", decodeTimestamp)
	time_str := time.UnixMilli(int64(decodeTimestamp))
	t.Logf("timestamp str: %s", time_str)

	timestampProof, err := beefy.GetTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	// t.Log("timestampProof: ", timestampProof)
	t.Logf("timestampProof len: %d", len(timestampProof.Proof))
	t.Logf("timestampProof at: %#x", timestampProof.At)

	// for _, proof := range timestampProof.Proof {
	// 	t.Logf("timestampProof proof: %#x", proof)
	// }

	proofs := make([][]byte, len(timestampProof.Proof))
	for _, proof := range timestampProof.Proof {
		proofs = append(proofs, proof[:])
	}
	t.Logf("timestampProof proofs: %#x", proofs)

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

	result, err := beefy.VerifyStateProof(proofs, decodeParachainHeader.StateRoot[:], paraTimestampStoragekey, timestamp)
	t.Log("beefy.VerifyStateProof(proof,root,key,value) result:", result)
	require.NoError(t, err)
	require.True(t, result)

	t.Log("--- test: build and verify timestamp proof ---")
	timestampWithProof, err := beefy.BuildTimestampProof(paraChainApi, paraChainBlockHash)
	require.NoError(t, err)
	t.Logf("beefy.BuildTimestamp(paraChainApi, paraChainBlockHash): %+v", timestampWithProof)
	// value3, err := trie_scale.Marshal(timestampWithProof.Value)
	require.NoError(t, err)
	ret, err := beefy.VerifyStateProof(timestampWithProof.Proofs, decodeParachainHeader.StateRoot[:], timestampWithProof.Key, timestampWithProof.Value)
	require.NoError(t, err)
	t.Log("beefy.VerifyStateProof(timestampWithProof.Proofs, decodeParachainHeader.StateRoot[:], timestampWithProof.Key, timestampWithProof.Value) result:", result)
	require.True(t, ret)
}
