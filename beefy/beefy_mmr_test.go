package beefy_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"log"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/ChainSafe/chaindb"
	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/merkle"
	"github.com/ComposableFi/go-merkle-trees/mmr"
	merkletypes "github.com/ComposableFi/go-merkle-trees/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/hash"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/dablelv/go-huge-util/conv"
	"github.com/ethereum/go-ethereum/crypto"
	beefy "github.com/octopus-network/beefy-go/beefy"
	trie_scale "github.com/octopus-network/trie-go/scale"
	"github.com/octopus-network/trie-go/trie"
	trie_proof "github.com/octopus-network/trie-go/trie/proof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMMRCodec(t *testing.T) {

	encodedMMRLeaf1 := "0xc50100430a0000fa6b428b97f17eb3c26b5ff93ac4aab01d025ada186dee56001b50c46c3eb6d1070100000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2b5dc72dfa5727322357a8fc8bbf2333c537d8359697a87c226b688356a193876"
	t.Logf("encodedMMRLeaf1: %s", encodedMMRLeaf1)
	var decodeMMREncodableOpaqueLeaf types.MMREncodableOpaqueLeaf
	err := codec.DecodeFromHex(encodedMMRLeaf1, &decodeMMREncodableOpaqueLeaf)
	require.NoError(t, err)
	t.Logf("decodeMMREncodableOpaqueLeaf: %+v", decodeMMREncodableOpaqueLeaf)
	mmrEncodableOpaqueLeaf, err := codec.EncodeToHex(decodeMMREncodableOpaqueLeaf)
	require.NoError(t, err)
	t.Logf("mmrEncodableOpaqueLeaf: %s", mmrEncodableOpaqueLeaf)

	var decodedMMRLeaf1 types.MMRLeaf
	err = codec.Decode(decodeMMREncodableOpaqueLeaf, &decodedMMRLeaf1)
	require.NoError(t, err)
	t.Logf("decodedMMRLeaf1: %+v", decodedMMRLeaf1)
	reEncodeMMRLeaf1, err := codec.Encode(decodedMMRLeaf1)
	require.NoError(t, err)
	t.Logf("reEncodeMMRLeaf1: %+v", reEncodeMMRLeaf1)

	encodableOpaqueLeaf, err := codec.EncodeToHex(reEncodeMMRLeaf1)
	require.NoError(t, err)
	t.Logf("encodableOpaqueLeaf: %s", encodableOpaqueLeaf)

	encodedMMRProof1 := "0x430a000000000000450a00000000000018736ae7c63f18a9fc6966b515bdf1f371834020d8a6fe97c104f2adec08d3329bb07acec2bec47370361e3778be0e0ba04eaf2cd2dc981667daad43a6af0186c33ef9c2f66b818725f3dbbd84a44038e07bd1c92fc283a1d16b2d9cf910cda6a9f638cfc7d21992e3ac2ffd563e2152c3a6a9d069b694700823e5eb673e840067fd2884921cd2121b4e2d65dac6556ae18efc9035eb43d26d963f40d9ee7a2a27608c545565b1f23989dca476bbf5aa2702bbe3e1725052328962401c64c15dae"
	var decodedProof1 types.MMRProof
	err = codec.DecodeFromHex(encodedMMRProof1, &decodedProof1)
	require.NoError(t, err)
	t.Logf("decodedProof1: %+v", decodedProof1)

	var tmp struct {
		BlockHash string `json:"blockHash"`
		Leaf      string `json:"leaf"`
		Proof     string `json:"proof"`
	}

	generateMMRProofResp := `{
		"blockHash": "0x6a9dc619f0b91ae3bb0c7fb73771769ad4423373b4d59c0cfa670db04ef8726a",
		"leaf": "0xc50100430a0000fa6b428b97f17eb3c26b5ff93ac4aab01d025ada186dee56001b50c46c3eb6d1070100000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2b5dc72dfa5727322357a8fc8bbf2333c537d8359697a87c226b688356a193876",
		"proof": "0x430a000000000000450a00000000000018736ae7c63f18a9fc6966b515bdf1f371834020d8a6fe97c104f2adec08d3329bb07acec2bec47370361e3778be0e0ba04eaf2cd2dc981667daad43a6af0186c33ef9c2f66b818725f3dbbd84a44038e07bd1c92fc283a1d16b2d9cf910cda6a9f638cfc7d21992e3ac2ffd563e2152c3a6a9d069b694700823e5eb673e840067fd2884921cd2121b4e2d65dac6556ae18efc9035eb43d26d963f40d9ee7a2a27608c545565b1f23989dca476bbf5aa2702bbe3e1725052328962401c64c15dae"
	  }`
	err = json.Unmarshal([]byte(generateMMRProofResp), &tmp)
	require.NoError(t, err)
	t.Logf("generateMMRProofResp Unmarshal: %+v", tmp)
	blockHash := &types.H256{}
	err = codec.DecodeFromHex(tmp.BlockHash, &blockHash)
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)

	encodedLeafByes2 := &types.MMREncodableOpaqueLeaf{}
	err = codec.DecodeFromHex(tmp.Leaf, &encodedLeafByes2)
	require.NoError(t, err)
	t.Logf("encodedLeafByes2: %+v", encodedLeafByes2)

	decodedMMRLeaf2 := &types.MMRLeaf{}
	err = codec.DecodeFromHex(tmp.Leaf, decodedMMRLeaf2)
	require.NoError(t, err)
	t.Logf("decodedMMRLeaf2: %+v", decodedMMRLeaf2)

	decodedProof2 := &types.MMRProof{}
	err = codec.DecodeFromHex(tmp.Proof, decodedProof2)
	require.NoError(t, err)
	t.Logf("decodedProof2: %+v", decodedProof2)
}

func TestMMRBatchCodec(t *testing.T) {

	var tmp struct {
		BlockHash string `json:"blockHash"`
		Leaves    string `json:"leaves"`
		Proof     string `json:"proof"`
	}

	generateMMRProofResp := ` {
		"blockHash": "0x95eafe803529840af91b66fbc6be7eb8a8c671f507548776e17cb355bba0adc4",
		"leaves": "0x0cc50100bc0100001e45989548036f39a91e721cbec35fa49272f1087ce2a4ed609a11b5a01da1042d0000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000c50100be0100001d9b4cb5b689ec8f735927050a838865f9d28cf732b1350f9c11495821f3d5af2d0000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000c50100c00100007f75a781074206f67a49b4bb1b12e05710eb840b07203e650e5d9bc2652852e32d0000000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a20000000000000000000000000000000000000000000000000000000000000000",
		"proof": "0x0cbc01000000000000be01000000000000c001000000000000c3010000000000002886a21085b42a98b824df9a91e0be11d206a5b75e97ee0ebc9bf6b41aeb8171b2bdd6717a04e4ecb21e1fbc820f5f193145b1cdbbd7d25d45a3977b3fbad1344239a24e5f8523e55247b096ea3f92067aa5234ceeac8b9d905da4c76876227fb62cad52d97797cc5129a2e3ea332e546abd77171d40e662e92b289fb08ec8764ff76b3eef3ec3d8a535de6a0b528cb6d5a4aa28944b312ed0f622287ad338997d36769bdfcb8594e84e422d957bf1f08e7030525a4ddd7e3127238b7db928dd52abe90fa037f5363f6cf3fd07ac59fa9df3587e2302f1ebfcc12dcb2ca62177c094d7345a81692c4afd8d05e0d5ed83d17201be6a5099341fcade2a162fe6fd35eb0265fba42510d287ae5710c9e0d03f64f7b651920b00314dc5f79dbc7676240347aab42873f9c7bd35fdc76b10c638e93223fb0847b1518383a474fff1570c"
	  }`
	err := json.Unmarshal([]byte(generateMMRProofResp), &tmp)
	require.NoError(t, err)
	t.Logf("generateMMRProofResp Unmarshal: %+v", tmp)

	blockHash := &types.H256{}
	err = codec.DecodeFromHex(tmp.BlockHash, &blockHash)
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)

	// var mmrLeaves []types.MMRLeaf
	// err = codec.DecodeFromHex(tmp.Leaves, &mmrLeaves)
	// require.NoError(t, err)
	// t.Logf("mmrLeaves: %+v", mmrLeaves)

	var opaqueLeaves [][]byte
	err = codec.DecodeFromHex(tmp.Leaves, &opaqueLeaves)
	require.NoError(t, err)
	t.Logf("opaqueLeaves: %+v", opaqueLeaves)
	type ParentNumberAndHash struct {
		ParentNumber types.U32
		Hash         types.Hash
	}
	type MMRLeaf struct {
		Version               types.MMRLeafVersion
		ParentNumberAndHash   ParentNumberAndHash
		BeefyNextAuthoritySet types.BeefyNextAuthoritySet
		ParachainHeads        types.H256
	}
	var leaves []MMRLeaf
	for _, leaf := range opaqueLeaves {

		var mmrLeaf MMRLeaf
		err := codec.Decode(leaf, &mmrLeaf)
		require.NoError(t, err)
		t.Logf("mmrleaf: %+v", mmrLeaf)
		leaves = append(leaves, mmrLeaf)
	}
	t.Logf("leaves: %+v", leaves)

	type MMRBatchProof struct {
		// The index of the leaf the proof is for.
		LeafIndexes []types.U64
		// Number of leaves in MMR, when the proof was generated.
		LeafCount types.U64
		// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
		Items []types.H256
	}
	decodedProof := &MMRBatchProof{}
	err = codec.DecodeFromHex(tmp.Proof, decodedProof)
	require.NoError(t, err)
	t.Logf("decodedProof: %+v", decodedProof)
}

func TestGetBeefyFinalizedHead(t *testing.T) {
	// The following example shows how to instantiate a Substrate API and use it to connect to a node
	api, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)

	beefyFinalizedHeadHash, err := beefy.GetBeefyFinalizedHead(api)
	require.NoError(t, err)

	beefyFinalizedHeader, err := api.RPC.Chain.GetHeader(beefyFinalizedHeadHash)
	require.NoError(t, err)
	t.Logf("beefy finalized head hash: %#x", beefyFinalizedHeadHash)
	t.Logf("beefy finalized head nubmer: %d", beefyFinalizedHeader.Number)
	// t.Logf("beefy finalized header: %+v", beefyFinalizedHeader)

}

func TestVerifyMMR(t *testing.T) {
	encodeVersionedFinalityProof := "0x01046d68807a9e44f5ce2abbbb835d421aa30fbd208128ae6382094eb7b5c0e06c5bed30ae630f0000890100000000000004b8050000001012f5b0f14c5d821bb57e136a35eedc1e1a594a03729c3c67ff19a0c0c2c9696a0b27cbed5f5e2f1484a23b01a0787c4b04fa85a1003a2170f638e1167994030201d91d5fd8305c7d55860cf4e82e7ca81ed32ea106df06d4590a45a98ee01c14797d8267f6db5c9a884cdb10389d5602eb2a6d8283079c8fbd011c54903095e62b0019f246b1f8ee13bfa73a5c436925298bdf0c3fb284fdb8c7ae70031cfb1c15fc18651ef32ce6cd23eee63f513bb1222d99b7f45f7ce7989b18d3c1040d0a02b70166ca3a7a8eefab0df53b4ca0630de24715ab5aefe15f197b6f9c74e33792082c5e7d48be6da4689a5cacdba73be6157eab6294886da8b64725862d478449786900"
	decodedVersionedFinalityProof := &beefy.VersionedFinalityProof{}
	err := codec.DecodeFromHex(encodeVersionedFinalityProof, decodedVersionedFinalityProof)
	require.NoError(t, err)
	t.Logf("decoded SignedCommitment: %+v", decodedVersionedFinalityProof)
	payload := decodedVersionedFinalityProof.SignedCommitment.Commitment.Payload[0]
	mmrRootID := payload.ID
	t.Logf("mmrRootID: %s", mmrRootID)
	mmrRoot := payload.Data
	t.Logf("mmrRoot:%#x", mmrRoot)
	blockNumber := decodedVersionedFinalityProof.SignedCommitment.Commitment.BlockNumber
	t.Logf("blockNumber: %d", blockNumber)
	bockHash := "0x63c06b2b5d56389ee657c47042471532b24a5be63c26e2deb0720d614c9aa444"
	t.Logf("bockHash: %s", bockHash)
	leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(0, blockNumber)
	t.Logf("leafIndex: %d", leafIndex)
	generateMMRProofRespJson := ` {
		"blockHash": "0x63c06b2b5d56389ee657c47042471532b24a5be63c26e2deb0720d614c9aa444",
		"leaf": "0xc50100620f0000e8558adaaa05d70887c329b8a427c3e6e8284f917ee31358c94be8539f05183d8a0100000000000005000000304803fa5a91d9852caafe04b4b867a4ed27a07a5bee3d1507b4b187a68777a2f898367940dfdd5a1306a3a8bc05fcddd04c897987b3722b9ef4b1c51c3e08af",
		"proof": "0x620f000000000000630f0000000000001c736ae7c63f18a9fc6966b515bdf1f371834020d8a6fe97c104f2adec08d3329b2fb97ae6e38a38066d7dc2398aaaf798bbce4b6055546682ce48e5d141d3ce143412395942e607866feab86db19e5d758dc2584c3985201cc923ffc7c40731f067d10dbb787f16d9d0162f17f3699adc5b6cf826f649f920c40d6ae8b857f0b6ed307e08b39cf647a304323491d14ad2a772bd0ea0951bfa47e09ed61c5c3a2cd25f7d9a91f2f19358e53619f7e721049ec576a0b303154e158ca04c88b02a15d449cd8873454989919a12dbc43dc3ef687d2140a50ad3533681269264e36f39"
	  }`

	generateMMRProofResp := types.GenerateMMRProofResponse{}
	err = generateMMRProofResp.UnmarshalJSON([]byte(generateMMRProofRespJson))
	require.NoError(t, err)
	t.Logf("generateMMRProofResp Unmarshal: %+v", generateMMRProofResp)

	blockHash, mmrLeaf, proof := generateMMRProofResp.BlockHash, generateMMRProofResp.Leaf, generateMMRProofResp.Proof
	t.Logf("blockHash: %#x", blockHash)
	t.Logf("mmrLeaf: %+v", mmrLeaf)
	t.Logf("mmrLeafProof: %+v", proof)

	proofLen := len(proof.Items)
	t.Logf("proofLen: %d", proofLen)
	var mmrLeafProof = make([][]byte, proofLen)
	for i := 0; i < proofLen; i++ {
		mmrLeafProof[i] = proof.Items[i][:]
	}
	t.Logf("mmrLeafProof: %+v", mmrLeafProof)

	// scale encode the mmr leaf
	encodedMMRLeaf, err := codec.Encode(mmrLeaf)
	require.NoError(t, err)
	t.Logf("encodedMMRLeaf: %+v", encodedMMRLeaf)
	mmrLeafBytes, err := codec.Encode(encodedMMRLeaf)
	require.NoError(t, err)
	t.Logf("mmrLeafBytes: %+v", mmrLeafBytes)

	// we treat this leaf as the latest leaf in the mmr
	mmrSize := mmr.LeafIndexToMMRSize(leafIndex)
	t.Logf("mmrSize:%d", mmrSize)
	mmrLeaves := []merkletypes.Leaf{
		{
			Hash:  crypto.Keccak256(encodedMMRLeaf),
			Index: leafIndex,
		},
	}
	mmrProof1 := mmr.NewProof(mmrSize, mmrLeafProof, mmrLeaves, hasher.Keccak256Hasher{})
	ret1 := mmrProof1.Verify(mmrRoot)
	t.Logf("mmrProof verify result :%#v", ret1)

	// mmrLeaves2 := []merkletypes.Leaf{
	// 	{
	// 		Hash:  crypto.Keccak256(mmrLeafBytes),
	// 		Index: leafIndex,
	// 	},
	// }
	// mmrProof2 := mmr.NewProof(mmrSize, mmrLeafProof, mmrLeaves2, hasher.Keccak256Hasher{})
	mmrProof2 := mmr.NewProof(mmrSize, mmrLeafProof, mmrLeaves, hasher.Keccak256Hasher{})
	calMMRRoot, err := mmrProof2.CalculateRoot()
	require.NoError(t, err)
	t.Logf("cal mmr root:%#x", calMMRRoot)
	t.Logf("payload.Data:%#x", payload.Data)
	require.Equal(t, calMMRRoot, mmrRoot)
	ret2 := reflect.DeepEqual(calMMRRoot, mmrRoot)
	t.Logf("reflect.DeepEqual result :%#v", ret2)
}

// verify relaychain header and parachain header
func TestVerifyMMRLocal(t *testing.T) {
	t.Skip()
	api, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	if err != nil {
		t.Logf("Connecting err: %v", err)
	}
	ch := make(chan interface{})
	sub, err := api.Client.Subscribe(
		context.Background(),
		"beefy",
		"subscribeJustifications",
		"unsubscribeJustifications",
		"justifications",
		ch)

	assert.NoError(t, err)
	if err != nil && err.Error() == "Method not found" {
		t.Logf("skipping since beefy module is not available")
	}

	t.Logf("subscribed to %s\n", beefy.LOCAL_RELAY_ENDPPOIT)
	// assert.NoError(t, err)
	defer sub.Unsubscribe()

	timeout := time.After(24 * time.Hour)
	received := 0
	// var preBlockNumber uint32
	// var preBloackHash types.Hash
	for {
		select {
		case msg := <-ch:
			t.Logf("encoded msg: %s\n", msg)

			s := &beefy.VersionedFinalityProof{}
			err := codec.DecodeFromHex(msg.(string), s)
			if err != nil {
				panic(err)
			}

			t.Logf("decoded msg: %+v", s)
			singedCommitmentblockNumber := s.SignedCommitment.Commitment.BlockNumber
			// t.Logf("blockNumber: %d", blockNumber)
			singedCommitmentBlockHash, err := api.RPC.Chain.GetBlockHash(uint64(singedCommitmentblockNumber))
			require.NoError(t, err)
			t.Logf("singedCommitmentblockNumber: %d singedCommitmentBlockHash: %#x", singedCommitmentblockNumber,
				singedCommitmentBlockHash)

			// if received == 0 {
			// 	t.Log("First received signed commitment,init client state and need to wait next msg!")
			// 	preBlockNumber = singedCommitmentblockNumber
			// 	preBloackHash = singedCommitmentBlockHash
			// 	received++
			// 	continue
			// }
			for targetHeight := uint64(singedCommitmentblockNumber); uint64(singedCommitmentblockNumber-2) < targetHeight; targetHeight-- {
				//target blocknumber
				// targetHeight := uint64(singedCommitmentblockNumber - 2)
				// targetHeight := beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), singedCommitmentblockNumber)
				// leafIndex := beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), singedCommitmentblockNumber)
				// leafIndex := beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), targetBlockNumber)
				// leafIndex := uint64(targetHeight)
				// t.Logf("mmrSize:%d\n ", mmrSize)
				// generate mmr proof for target height
				retHash, mmrLeaf, proof, err := beefy.BuildMMRProof(api, targetHeight-1, singedCommitmentBlockHash)
				// Note: get the mmr proof for target block number,must input target block number ,do not input LeafIndex
				// retHash, mmrLeaf, proof, err := beefy.BuildMMRProof(api, uint64(targetBlockNumber), singedCommitmentBlockHash)

				// leafCount := uint64(proof.LeafCount)
				leafIndex := uint64(proof.LeafIndex)
				mmrSize := mmr.LeafIndexToMMRSize(targetHeight - 1)
				t.Logf("singedCommitmentblockNumber: %d targetHeight: %d proof.LeafIndex: %d mmrSize: %d", singedCommitmentblockNumber, targetHeight, proof.LeafIndex, mmrSize)
				// parachainHeadsMerkleRoot := mmrLeaf.ParachainHeads
				// mmrSize1 := mmr.LeafIndexToMMRSize(leafIndex)
				// mmrSize2 := mmr.LeafIndexToMMRSize(leafCount)

				var mmrLeafProofItems = make([][]byte, len(proof.Items))
				for i := 0; i < len(proof.Items); i++ {
					mmrLeafProofItems[i] = proof.Items[i][:]
				}

				// t.Logf("singedCommitmentblockNumber:%d targetHeight:%d  proof.LeafIndex:%d proof.LeafCount:%d mmr.LeafIndexToMMRSize(leafIndex):%d mmr.LeafIndexToMMRSize(leafCount):%d mmrSize3 := mmr.LeafIndexToMMRSize(targetHeight):%d",
				// 	singedCommitmentblockNumber, targetHeight, proof.LeafIndex, leafCount, mmrSize1, mmrSize2, mmrSize3)
				require.NoError(t, err)
				t.Logf("\nrethash: %#x\nmmrLeaf: %+v\nmmrLeafProofItems: %+v", retHash, mmrLeaf, mmrLeafProofItems)

				// t.Log("------------------------------------------------------------------------------------")
				// t.Log("beefy.VerifyMMRProof(s.SignedCommitment, mmrSize1, leafIndex, mmrLeaf, mmrLeafProof)")
				// result1, err := beefy.VerifyMMRProof(s.SignedCommitment, mmrSize1, leafIndex, mmrLeaf, mmrLeafProof)
				// require.NoError(t, err)
				// require.True(t, result1)

				// // t.Logf("verify mmr proof result1: %#v", result1)
				// t.Log("------------------------------------------------------------------------------------")
				// t.Log("beefy.VerifyMMRProof(s.SignedCommitment, mmrSize2, leafIndex, mmrLeaf, mmrLeafProof)")
				// result2, err := beefy.VerifyMMRProof(s.SignedCommitment, mmrSize2, leafIndex, mmrLeaf, mmrLeafProof)
				// require.NoError(t, err)
				// require.True(t, result2)

				// t.Logf("verify mmr proof result2: %#v", result2)
				// t.Log("------------------------------------------------------------------------------------")
				// t.Log("beefy.VerifyMMRProof(s.SignedCommitment, mmrSize3, leafIndex, mmrLeaf, mmrLeafProof)")
				t.Log("------------------------------------------------------------------------------------")
				result3, err := beefy.VerifyMMRProof(s.SignedCommitment.Commitment, mmrSize, leafIndex, mmrLeaf, mmrLeafProofItems)
				t.Log("------------------------------------------------------------------------------------")
				require.NoError(t, err)
				require.True(t, result3)

				// t.Logf("verify mmr proof result3: %#v", result3)
				// t.Log("------------------------------------------------------------------------------------")
				// t.Log("beefy.VerifyMMRProof(s.SignedCommitment, mmrSize4, leafIndex, mmrLeaf, mmrLeafProof)")
				// result4, err := beefy.VerifyMMRProof(s.SignedCommitment, mmrSize3, targetHeight, mmrLeaf, mmrLeafProof)
				// require.NoError(t, err)
				// require.True(t, result4)

				// verify parachain header
				// get target block hash
				leafBlockHash, err := api.RPC.Chain.GetBlockHash(leafIndex)
				require.NoError(t, err)
				t.Logf("leafBlockNumber: %d leafBlockHash: %#x", leafIndex, leafBlockHash)
				paraChainIds, err := beefy.GetParachainIds(api, leafBlockHash)
				require.NoError(t, err)
				t.Logf("paraChainIds: %+v", paraChainIds)
				var paraChainHeaderMap = make(map[uint32][]byte, len(paraChainIds))
				for _, paraChainId := range paraChainIds {
					paraChainHeader, err := beefy.GetParachainHeader(api, uint32(paraChainId), leafBlockHash)
					require.NoError(t, err)
					// t.Logf("paraChainId: %d", paraChainId)
					t.Logf("paraChainId: %d paraChainHeader: %#x", paraChainId, paraChainHeader)
					paraChainHeaderMap[paraChainId] = paraChainHeader
				}
				t.Logf("paraChainHeaderMap: %+v", paraChainHeaderMap)
				// sort by paraId
				var sortedParaIds []uint32
				for paraId := range paraChainHeaderMap {
					sortedParaIds = append(sortedParaIds, paraId)
				}
				sort.SliceStable(sortedParaIds, func(i, j int) bool {
					return sortedParaIds[i] < sortedParaIds[j]
				})
				t.Logf("sortedParaIds: %+v", sortedParaIds)

				var paraHeaderLeaves [][]byte
				var targetParaHeaderindex uint32
				var targetParaId uint32 = 2222
				count := 0
				for _, paraId := range sortedParaIds {
					encodedParaHeader, err := codec.Encode(beefy.ParaIdAndHeader{ParaId: paraId, Header: paraChainHeaderMap[paraId]})
					require.NoError(t, err)
					// get paraheader hash
					paraHeaderLeaf := crypto.Keccak256(encodedParaHeader)
					paraHeaderLeaves = append(paraHeaderLeaves, paraHeaderLeaf)
					if paraId == targetParaId {
						// find the index of targent para chain id
						targetParaHeaderindex = uint32(count)
						log.Printf("targetParaHeaderindex: %d", targetParaHeaderindex)
					}
					count++
				}
				log.Printf("paraHeadsLeaves: %+v", paraHeaderLeaves)
				// build merkle tree from all the paraheader leaves
				tree, err := merkle.NewTree(hasher.Keccak256Hasher{}).FromLeaves(paraHeaderLeaves)
				require.NoError(t, err)

				parachainHeadsMerkleRoot := mmrLeaf.ParachainHeads
				t.Log("------------------------------------------------------------------------------------")
				t.Logf("cal paraHeaders merkle tree root: %#x", tree.Root())
				t.Logf("parachainHeadsMerkleRoot from mmrLeaf: %#x", parachainHeadsMerkleRoot)
				t.Log("------------------------------------------------------------------------------------")

				// check target blockhash == mmrLeaf.
				targetRelayerBlockHash, err := api.RPC.Chain.GetBlockHash(targetHeight)
				require.NoError(t, err)
				targetRelayHeader, err := api.RPC.Chain.GetHeader(targetRelayerBlockHash)
				require.NoError(t, err)
				t.Logf("\targetHeight: %d targetRelayerBlockHash: %#x\n targetRelayHeader: %+v", targetHeight, targetRelayerBlockHash, targetRelayHeader)

				t.Logf("\ntargetRelayerBlockHash: %#x", targetRelayerBlockHash)
				t.Logf("targetRelayerHeader.ParentHash: %#x", targetRelayHeader.ParentHash)
				t.Logf("mmrLeaf ParentNumber: %d, mmrLeaf parent Hash: %#x", mmrLeaf.ParentNumberAndHash.ParentNumber, mmrLeaf.ParentNumberAndHash.Hash)

				encodeTargetRelayerHeader, err := codec.Encode(targetRelayHeader)
				require.NoError(t, err)
				// targetRelayHeaderRehash, err := hasher.Keccak256Hasher{}.Hash(encodeTargetRelayerHeader)
				blake2b256, err := hash.NewBlake2b256(nil)
				require.NoError(t, err)
				_, err = blake2b256.Write(encodeTargetRelayerHeader)
				targetRelayHeaderRehash := blake2b256.Sum(nil)
				require.NoError(t, err)
				t.Logf("targetRelayHeaderRehash: %#x", targetRelayHeaderRehash)

				leafHeader, err := api.RPC.Chain.GetHeader(leafBlockHash)
				require.NoError(t, err)
				t.Logf("leafHeader: %+v", leafHeader)

				// encode
				ecodedLeafHeader, err := codec.Encode(leafHeader)
				require.NoError(t, err)
				// get blake2b256 hash
				// targetRelayHeaderRehash, err := hasher.Keccak256Hasher{}.Hash(encodeTargetRelayerHeader)
				blake2b256, err = hash.NewBlake2b256(nil)
				require.NoError(t, err)
				_, err = blake2b256.Write(ecodedLeafHeader)
				leafHeaderRehash := blake2b256.Sum(nil)
				require.NoError(t, err)
				t.Logf("leafHeaderRehash: %#x", leafHeaderRehash)
				t.Logf("\nleafIndex: %d mmrLeaf ParentNumber: %d leafBlockHash: %#x\n mmrLeaf parent Hash: %#x\n leafHeader: %+v", leafIndex, mmrLeaf.ParentNumberAndHash.ParentNumber, leafBlockHash, mmrLeaf.ParentNumberAndHash.Hash, leafHeader)
			}

			received++

			if received >= 2 {
				return
			}
		case <-timeout:
			t.Logf("timeout reached without getting 2 notifications from subscription")
			return
		}
	}
}

// verify mmr proof,relaychain header,parachain header proof and parachain state proof
func TestVerifyMMRLocal2(t *testing.T) {
	// t.Skip()
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	t.Logf("subscribed to %s\n", beefy.LOCAL_RELAY_ENDPPOIT)
	paraChainApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_PARACHAIN_ENDPOINT)
	require.NoError(t, err)
	t.Logf("subscribed to %s\n", beefy.LOCAL_PARACHAIN_ENDPOINT)
	ch := make(chan interface{})
	sub, err := relayApi.Client.Subscribe(
		context.Background(),
		"beefy",
		"subscribeJustifications",
		"unsubscribeJustifications",
		"justifications",
		ch)
	require.NoError(t, err)

	defer sub.Unsubscribe()

	timeout := time.After(24 * time.Hour)
	received := 0

	for {
		select {
		case msg := <-ch:
			t.Logf("encoded msg: %s\n", msg)

			s := &beefy.VersionedFinalityProof{}
			err := codec.DecodeFromHex(msg.(string), s)
			require.NoError(t, err)
			t.Logf("decoded msg: %+v", s)
			singedCommitmentblockNumber := s.SignedCommitment.Commitment.BlockNumber
			// t.Logf("blockNumber: %d", blockNumber)
			singedCommitmentBlockHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(singedCommitmentblockNumber))
			require.NoError(t, err)
			t.Logf("singedCommitmentblockNumber: %d singedCommitmentBlockHash: %#x", singedCommitmentblockNumber, singedCommitmentBlockHash)

			//target blocknumber
			// targetBlockNumber := singedCommitmentblockNumber - 5
			// leafIndex := beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), singedCommitmentblockNumber)
			leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(uint32(beefy.BEEFY_ACTIVATION_BLOCK), singedCommitmentblockNumber)

			// t.Logf("mmrSize:%d\n ", mmrSize)
			// retHash, mmrLeaf, proof, err := beefy.BuildMMRProof(api, leafIndex, blockHash)
			// Note: get the mmr proof for target block number,must input target block number ,do not input LeafIndex
			// retHash, mmrLeaf, proof, err := beefy.BuildMMRProof(relayApi, uint64(targetBlockNumber), singedCommitmentBlockHash)
			targetHeights := []uint32{uint32(singedCommitmentblockNumber - 1)}
			mmrBatchProof, err := beefy.BuildMMRProofs(relayApi, targetHeights,
				types.NewOptionU32(types.U32(singedCommitmentblockNumber)), types.NewOptionHashEmpty())

			leafCount := mmrBatchProof.Proof.LeafCount
			// parachainHeadsMerkleRoot := mmrLeaf.ParachainHeads
			mmrSize1 := mmr.LeafIndexToMMRSize(leafIndex)
			mmrSize2 := mmr.LeafIndexToMMRSize(uint64(leafCount))

			var mmrLeafProof = make([][]byte, len(mmrBatchProof.Proof.Items))
			for i := 0; i < len(mmrBatchProof.Proof.Items); i++ {
				mmrLeafProof[i] = mmrBatchProof.Proof.Items[i][:]
			}

			t.Logf("singedCommitmentblockNumber:%d targetBlockNumber:%d leafIndex:%d proof.LeafIndex:%d leafCount:%d mmrSize1:%d mmrSize2:%d",
				singedCommitmentblockNumber, targetHeights, leafIndex, mmrBatchProof.Proof.LeafIndexes, leafCount, mmrSize1, mmrSize2)
			require.NoError(t, err)
			t.Logf("\nrethash: %#x\nmmrLeaf: %+v\nmmrLeafProof: %+v", mmrBatchProof.BlockHash, mmrBatchProof.Leaves, mmrLeafProof)

			// step1: verfiy relayer chain mmr proof
			// result1, err := beefy.VerifyMMRProof(s.SignedCommitment, mmrSize1, leafIndex, mmrLeaf, mmrLeafProof)
			// require.NoError(t, err)
			// t.Logf("verify mmr proof result: %#v", result1)
			t.Log("--- Begin to verify relayer chain mmr proof ---")
			//verify mmr batch proof
			result, err := beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload[0].Data, mmrSize1,
				mmrBatchProof.Leaves, mmrBatchProof.Proof)
			require.NoError(t, err)
			t.Logf("beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload[0], mmrSize,mmrBatchProof.Leaves, mmrBatchProof.Proof) result: %+v", result)
			require.True(t, result)
			t.Logf("verify mmr proof result: %#v", result)

			t.Log("--- End to verify relayer chain mmr proof --- \n")

			// step2: verify parachain header at target height
			// get target block hash
			t.Log("--- Begin to verify relayer chain header ---")
			// targetBlockHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(targetBlockNumber))
			// require.NoError(t, err)
			// t.Logf("targetBlockNumber: %d targetBlockHash: %#x", targetBlockNumber, targetBlockHash)
			targetRelayerHeader, err := relayApi.RPC.Chain.GetHeader(singedCommitmentBlockHash)
			require.NoError(t, err)
			t.Logf("targetBlockHash: %#x\n targetRelayerHeader: %+v", singedCommitmentBlockHash, targetRelayerHeader)
			t.Logf("targetRelayerHeader.ParentHash: %#x", targetRelayerHeader.ParentHash)
			t.Logf("mmrLeaf.ParentNumberAndHash.Hash: %#x", mmrBatchProof.Leaves[0].ParentNumberAndHash.Hash)
			t.Log("--- End to verify relayer chain header --- \n")

			// step3: verify parachain header at target height
			t.Log("--- Begin to verify para chain header ---")
			targetEncodedParaHeader, err := beefy.GetParachainHeader(relayApi, uint32(beefy.LOCAL_PARACHAIN_ID), singedCommitmentBlockHash)
			// It`s possobile there is not parachain header at target height
			require.NoError(t, err)
			t.Logf("targetBlockHash: %#x\n targetParaHeader: %#x", singedCommitmentBlockHash, targetEncodedParaHeader)
			// decode header
			var targetDecodedParaHeader types.Header
			err = codec.Decode(targetEncodedParaHeader, &targetDecodedParaHeader)
			require.NoError(t, err)
			t.Logf("targetEncodedParaHeader: %+v", targetDecodedParaHeader)

			// encode header by substrate.Marshal
			// marShalTargetParaHeader, err := trie_scale.Marshal(targetDecodedParaHeader)
			// require.NoError(t, err)
			// t.Logf("marShalTargetParaHeader: %#x", marShalTargetParaHeader)

			// get parachain state proof at target height
			targetParaHeaderStateProof, err := beefy.GetParachainHeaderProof(relayApi, singedCommitmentBlockHash, beefy.LOCAL_PARACHAIN_ID)
			require.NoError(t, err)
			t.Logf("targetParaHeaderStateProof: %+v", targetParaHeaderStateProof)
			paraHeaderStateproofs := make([][]byte, len(targetParaHeaderStateProof.Proof))
			for _, proof := range targetParaHeaderStateProof.Proof {
				paraHeaderStateproofs = append(paraHeaderStateproofs, proof[:])
			}

			// relayerHeaderStateTrieProof, err := trie_proof.BuildTrie(paraHeaderStateproofs, targetRelayerHeader.StateRoot[:])
			// t.Log("relayer chain Header Trie proof:\n", relayerHeaderStateTrieProof)
			// require.NoError(t, err)

			meta, err := relayApi.RPC.State.GetMetadataLatest()
			require.NoError(t, err)
			paraIdEncoded := make([]byte, 4)
			binary.LittleEndian.PutUint32(paraIdEncoded, beefy.LOCAL_PARACHAIN_ID)
			targetParaHeaderKey, err := types.CreateStorageKey(meta, "Paras", "Heads", paraIdEncoded)
			require.NoError(t, err)
			log.Printf("targetParaHeaderKey: %#x", targetParaHeaderKey)
			// find the parachain header
			// paraHeaderValue := relayerHeaderStateTrieProof.Get(targetParaHeaderKey)
			// require.NotEmpty(t, paraHeaderValue)
			// t.Logf("The targetParaHeader value from trie proof: %#x", paraHeaderValue)
			// // decode the target para chain header
			// var targetParaHeader = substrate.NewEmptyHeader()
			// err = trie_scale.Unmarshal(paraHeaderValue, &targetParaHeader)
			// require.NoError(t, err)
			// t.Logf("targetParaHeader: %+v", targetParaHeader)

			// err = trie_proof.Verify(paraHeaderStateproofs, targetRelayerHeader.StateRoot[:], targetParaHeaderKey, paraHeaderValue)
			//TODO: must be encoded again!?
			marShalTargetParaHeader, err := trie_scale.Marshal(targetEncodedParaHeader)
			require.NoError(t, err)
			t.Logf("marShalTargetParaHeader: %#x", marShalTargetParaHeader)
			err = trie_proof.Verify(paraHeaderStateproofs, targetRelayerHeader.StateRoot[:], targetParaHeaderKey, marShalTargetParaHeader)
			require.NoError(t, err)
			t.Log("trie_proof.Verify(paraHeaderStateproofs, targetRelayerHeader.StateRoot[:], targetParaHeaderKey, marShalTargetParaHeader) successlly!")
			//verify testing
			targetParaHeaderTrie := trie.NewEmptyTrie()
			database, err := chaindb.NewBadgerDB(&chaindb.Config{
				InMemory: true,
			})
			require.NoError(t, err)

			err = targetParaHeaderTrie.WriteDirty(database)
			require.NoError(t, err)
			calRelayerStateRoot, err := targetParaHeaderTrie.Hash()
			require.NoError(t, err)
			t.Logf("cal relayer state root from trie proof: %s", calRelayerStateRoot)
			t.Logf("targetRelayerHeader.StateRoot: %#x", targetRelayerHeader.StateRoot)

			t.Log("--- End to verify para chain header --- \n")

			// step4: verify parachain data
			t.Log("--- Begin to verify para chain state proof ---")
			t.Log("--- get parachain timestamp and proof from parachain ---")
			require.NoError(t, err)
			paraChainBlockHash, err := paraChainApi.RPC.Chain.GetBlockHash(uint64(targetDecodedParaHeader.Number))
			require.NoError(t, err)
			t.Logf("parachain height: %d,parachain BlockHash: %#x", targetDecodedParaHeader.Number, paraChainBlockHash)
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

			timestampTrieProof, err := trie_proof.BuildTrie(proofs, targetDecodedParaHeader.StateRoot[:])
			t.Logf("TimestampTrieProof: %+v", timestampTrieProof)
			require.NoError(t, err)

			timestampValue := timestampTrieProof.Get(paraTimestampStoragekey)
			t.Logf("the timestamp in the tire proof: %x", timestampValue)
			var timestamp2 uint64
			err = trie_scale.Unmarshal(timestampValue, &timestamp2)
			if err != nil {
				panic(err)
			}
			marshalTimestamp, err := trie_scale.Marshal(timestamp)
			require.NoError(t, err)
			t.Logf("cal timestamp from trie proof: %d hex: %x trie_scale.Marshal(timestamp): %+v", timestamp2, timestamp2, marshalTimestamp)
			// time_str := time.UnixMicro(int64(timestamp))
			time_str2 := time.UnixMilli(int64(timestamp2))
			// time_str := time.Unix(int64(timestamp), 0)
			t.Logf("cal timestamp from trie proof: %s\n", time_str2)

			//verify testing
			timestampTrie := trie.NewEmptyTrie()
			database2, err := chaindb.NewBadgerDB(&chaindb.Config{
				InMemory: true,
			})
			require.NoError(t, err)

			err = timestampTrie.WriteDirty(database2)
			require.NoError(t, err)
			rootHash, err := timestampTrie.Hash()
			t.Logf("cal parachain state root from new trie tree(rootHash): %#x", rootHash)
			require.NoError(t, err)
			marshalRootHash, err := trie_scale.Marshal(rootHash)
			require.NoError(t, err)
			t.Logf("cal parachain state root from new trie tree(marshalRootHash): %#x", marshalRootHash)
			t.Logf("targetDecodeParaHeader.StateRoot: %#x", targetDecodedParaHeader.StateRoot)

			err = trie_proof.Verify(proofs, targetDecodedParaHeader.StateRoot[:], paraTimestampStoragekey, marshalTimestamp)
			require.NoError(t, err)
			t.Log("trie_proof.Verify(proofs, targetDecodedParaHeader.StateRoot[:], paraTimestampStoragekey, marshalTimestamp) successlly!")
			t.Log("--- End to verify para chain state proof --- \n")

			received++
			if received >= 2 {
				return
			}
		case <-timeout:
			t.Logf("timeout reached without getting 2 notifications from subscription")
			return
		}
	}
}

func TestBuildMMRBatchProof(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)

	blockHash, err := api.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	header, err := api.RPC.Chain.GetHeader(blockHash)
	require.NoError(t, err)
	t.Logf("header number: %d", header.Number)
	// require.NoError(t, err)
	// t.Logf("blockHash: %#x", blockHash)
	blockNumbers := []uint32{uint32(header.Number) - 6, uint32(header.Number) - 4, uint32(header.Number) - 2}
	// idxes := []types.BlockNumber{header.Number - 6, header.Number - 4, header.Number - 2}
	t.Logf("idxes: %+v", blockNumbers)
	require.NoError(t, err)
	// batchProof, err := beefy.BuildMMRBatchProof(api, blockHash, idxes)
	// var nilHash types.Hash
	var proofsResp1 beefy.MmrProofsResp
	err = api.Client.Call(&proofsResp1, "mmr_generateProof", blockNumbers, uint32(header.Number), blockHash)
	// batchProof, err := beefy.BuildMMRProofs(api, idxes, types.NewOptionU32Empty(), types.NewOptionHashEmpty())
	require.NoError(t, err)
	t.Logf("blockNumbers: %+v", blockNumbers)
	t.Logf("best known blockNumber: %d", uint32(header.Number))
	t.Logf("requst blockHash: %+v", blockHash)
	t.Logf("proofResp1.blockHash: %#x", proofsResp1.BlockHash)

	proofsResp2, err := beefy.BuildMMRProofs(api, blockNumbers, types.NewOptionU32Empty(), types.NewOptionHashEmpty())
	require.NoError(t, err)
	t.Logf("blockNumbers: %+v", blockNumbers)
	t.Logf("best known blockNumber: %+v", types.NewOptionU32Empty())
	t.Logf("requst blockHash: %+v", types.NewOptionHashEmpty())
	t.Logf("proofResp2.blockHash: %#x", proofsResp2.BlockHash)

	proofsResp3, err := beefy.BuildMMRProofs(api, blockNumbers, types.NewOptionU32(types.U32(header.Number)), types.NewOptionHashEmpty())
	require.NoError(t, err)
	t.Logf("blockNumbers: %+v", blockNumbers)
	t.Logf("best known blockNumber: %+v", types.NewOptionU32(types.U32(header.Number)))
	t.Logf("requst blockHash: %+v", types.NewOptionHashEmpty())
	t.Logf("proofResp3.blockHash: %#x", proofsResp3.BlockHash)

	proofsResp4, err := beefy.BuildMMRProofs(api, blockNumbers, types.NewOptionU32(types.U32(header.Number)), types.NewOptionHash(blockHash))
	require.NoError(t, err)
	t.Logf("blockNumbers: %+v", blockNumbers)
	t.Logf("best known blockNumber: %+v", types.NewOptionU32(types.U32(header.Number)))
	t.Logf("requst blockHash: %+v", types.NewOptionHash(blockHash))
	t.Logf("proofResp4.blockHash: %#x", proofsResp4.BlockHash)
	require.Equal(t, proofsResp1, proofsResp4)
	require.Equal(t, proofsResp3.Leaves, proofsResp4.Leaves)
	require.Equal(t, proofsResp3.Proof, proofsResp4.Proof)

}

func TestVerifyMMRBatchProofLocal(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	if err != nil {
		t.Logf("Connecting err: %v", err)
	}
	ch := make(chan interface{})
	sub, err := api.Client.Subscribe(
		context.Background(),
		"beefy",
		"subscribeJustifications",
		"unsubscribeJustifications",
		"justifications",
		ch)

	require.NoError(t, err)

	t.Logf("subscribed to %s\n", beefy.LOCAL_RELAY_ENDPPOIT)

	defer sub.Unsubscribe()

	timeout := time.After(24 * time.Hour)
	received := 0
	var preBlockNumber uint32
	var preBloackHash types.Hash
	for {
		select {
		case msg := <-ch:
			t.Logf("encoded msg: %s", msg)

			s := &beefy.VersionedFinalityProof{}
			err := codec.DecodeFromHex(msg.(string), s)
			if err != nil {
				panic(err)
			}

			t.Logf("decoded msg: %+v\n", s)
			latestSignedCommitmentBlockNumber := s.SignedCommitment.Commitment.BlockNumber
			// t.Logf("blockNumber: %d\n", latestBlockNumber)
			latestSignedCommitmentBlockHash, err := api.RPC.Chain.GetBlockHash(uint64(latestSignedCommitmentBlockNumber))
			require.NoError(t, err)
			t.Logf("latestSignedCommitmentBlockNumber: %d latestSignedCommitmentBlockHash: %#x",
				latestSignedCommitmentBlockNumber, latestSignedCommitmentBlockHash)

			if received == 0 {
				t.Log("First received signed commitment,init client state and need to wait next msg!")
				preBlockNumber = latestSignedCommitmentBlockNumber
				preBloackHash = latestSignedCommitmentBlockHash
				received++
				continue
			}

			fromBlockNumber := preBlockNumber + 1
			t.Logf("fromBlockNumber: %d toBlockNumber: %d", fromBlockNumber, latestSignedCommitmentBlockNumber)

			fromBlockHash, err := api.RPC.Chain.GetBlockHash(uint64(fromBlockNumber))
			require.NoError(t, err)
			t.Logf("fromBlockHash: %#x ", fromBlockHash)
			t.Logf("preSignedCommitmentBloackHash: %#x ", preBloackHash)
			// t.Logf("toBlockNumber: %d", toBlockNumber)
			t.Logf("toBlockHash: %#x", latestSignedCommitmentBlockHash)

			changeSets, err := beefy.QueryParachainStorage(api, beefy.LOCAL_PARACHAIN_ID, fromBlockHash, latestSignedCommitmentBlockHash)
			require.NoError(t, err)
			t.Logf("changeSet len: %d", len(changeSets))
			var targetRelayChainBlockHeights []uint32
			for _, changeSet := range changeSets {
				header, err := api.RPC.Chain.GetHeader(changeSet.Block)
				require.NoError(t, err)
				// t.Logf("fromBlockHash: %#x ", fromFinalizedHash)
				t.Logf("changeSet blockHash: %d changeSet blockHash: %#x", header.Number, changeSet.Block)
				hexStr, err := json.Marshal(changeSet.Changes)
				require.NoError(t, err)
				t.Logf("changeSet changes: %s", hexStr)
				for _, change := range changeSet.Changes {

					t.Logf("change.StorageKey: %#x", change.StorageKey)
					t.Log("change.HasStorageData: ", change.HasStorageData)
					t.Logf("change.HasStorageData: %#x", change.StorageData)
				}
				targetRelayChainBlockHeights = append(targetRelayChainBlockHeights, uint32(header.Number))

			}
			t.Logf("targetRelayChainBlockHeights: %+v", targetRelayChainBlockHeights)
			// build mmr proofs for leaves containing target paraId
			// var mmrBatchProof beefy.MmrProofsResp
			// err = api.Client.Call(&mmrBatchProof, "mmr_generateProof", targetRelayChainBlockHeights,
			// uint32(latestSignedCommitmentBlockNumber), latestSignedCommitmentBlockHash)
			mmrBatchProof, err := beefy.BuildMMRProofs(api, targetRelayChainBlockHeights,
				types.NewOptionU32(types.U32(latestSignedCommitmentBlockNumber)), types.NewOptionHashEmpty())

			require.NoError(t, err)
			// t.Logf("mmrBatchProof: %+v", mmrBatchProof)
			t.Logf("mmrBatchProof.BlockHash: %#x", mmrBatchProof.BlockHash)
			t.Logf("mmrBatchProof leaves len: %d", len(mmrBatchProof.Leaves))
			for _, leaf := range mmrBatchProof.Leaves {
				t.Logf("mmrBatchProof leaf: %+v", leaf)
			}
			t.Logf("targetRelayChainBlockHeights: %+v", targetRelayChainBlockHeights)
			t.Logf("The indexes of the leaf the proof is for: %+v", mmrBatchProof.Proof.LeafIndexes)
			t.Logf("Number of leaves in MMR, when the proof was generated: %d", mmrBatchProof.Proof.LeafCount)
			// leafCount := mmrBatchProof.Proof.LeafCount
			// leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(uint32(beefy.BEEFY_ACTIVATION_BLOCK), uint32(leafCount))
			// mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
			// t.Logf("mmrSize: %d", mmrSize)

			leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(uint32(beefy.BEEFY_ACTIVATION_BLOCK), latestSignedCommitmentBlockNumber)
			mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
			t.Logf("beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), latestSignedCommitmentBlockNumber): %d", leafIndex)
			t.Logf("mmrSize: %d", mmrSize)

			var mmrLeafProof = make([][]byte, len(mmrBatchProof.Proof.Items))
			for i := 0; i < len(mmrBatchProof.Proof.Items); i++ {
				mmrLeafProof[i] = mmrBatchProof.Proof.Items[i][:]
			}

			var mmrLeaves = make([]merkletypes.Leaf, len(mmrBatchProof.Leaves))
			for i := 0; i < len(mmrBatchProof.Leaves); i++ {
				// scale encode the mmr leaf
				encodedMMRLeaf, err := codec.Encode(mmrBatchProof.Leaves[i])
				require.NoError(t, err)
				log.Printf("encodedMMRLeaf: %#x", encodedMMRLeaf)
				mmrLeaf := merkletypes.Leaf{
					Hash:  crypto.Keccak256(encodedMMRLeaf),
					Index: uint64(mmrBatchProof.Proof.LeafIndexes[i]),
				}
				mmrLeaves[i] = mmrLeaf
			}

			// CalculateRoot
			mmrProof := mmr.NewProof(mmrSize, mmrLeafProof, mmrLeaves, hasher.Keccak256Hasher{})
			calMMRRoot, err := mmrProof.CalculateRoot()
			require.NoError(t, err)
			t.Log("------------------------------------------------------------------------------------")
			t.Logf("cal mmr root:%#x", calMMRRoot)
			t.Logf("payload.Data:%#x", s.SignedCommitment.Commitment.Payload[0].Data)
			t.Log("------------------------------------------------------------------------------------")

			//verify mmr batch proof
			result, err := beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload[0].Data, mmrSize,
				mmrBatchProof.Leaves, mmrBatchProof.Proof)
			require.NoError(t, err)
			t.Logf("beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload[0], mmrSize,mmrBatchProof.Leaves, mmrBatchProof.Proof) result: %+v", result)
			require.True(t, result)

			// save latestSignedCommitment for next verify
			preBlockNumber = latestSignedCommitmentBlockNumber
			preBloackHash = latestSignedCommitmentBlockHash

			received++

			if received >= 3 {
				return
			}
		case <-timeout:
			t.Logf("timeout reached without getting 2 notifications from subscription")
			return
		}
	}
}

func TestVerifyMMR2(t *testing.T) {

	// PayloadItem ...
	// type PayloadItem struct {
	// 	ID   [2]byte
	// 	Data []byte
	// }
	payloadItem := []types.PayloadItem{
		{
			ID:   [2]byte{109, 104},
			Data: conv.SplitStrToSlice[byte]("24 231 138 237 85 84 129 228 66 190 34 109 217 224 57 22 86 173 92 20 229 33 44 214 144 248 61 171 77 38 180 142", " "),
		},
	}

	// type Commitment struct {
	// 	Payload        []PayloadItem
	// 	BlockNumber    uint32
	// 	ValidatorSetID uint64
	// }
	commitment := types.Commitment{
		Payload:        payloadItem,
		BlockNumber:    57,
		ValidatorSetID: 5,
	}
	var mmrSize1 uint64 = 109

	// type MMRLeaf struct {
	// 	Version               MMRLeafVersion
	// 	ParentNumberAndHash   ParentNumberAndHash
	// 	BeefyNextAuthoritySet BeefyNextAuthoritySet
	// 	ParachainHeads        H256
	// }

	// type ParentNumberAndHash struct {
	// 	ParentNumber U32
	// 	Hash         Hash
	// }

	// type BeefyNextAuthoritySet struct {
	// 	// ID
	// 	ID U64
	// 	// Number of validators in the set.
	// 	Len U32
	// 	// Merkle Root Hash build from BEEFY uncompressed AuthorityIds.
	// 	Root H256
	// }

	mmrLeaves1 := []types.MMRLeaf{
		{
			Version: 0,
			ParentNumberAndHash: types.ParentNumberAndHash{
				ParentNumber: 55,
				Hash:         types.NewHash(conv.SplitStrToSlice[byte]("121 32 210 187 76 47 46 211 65 164 4 188 42 249 229 121 232 213 67 244 48 139 215 192 8 249 20 188 66 193 119 56", " ")),
			},
			BeefyNextAuthoritySet: types.BeefyNextAuthoritySet{
				ID:   6,
				Len:  5,
				Root: types.NewH256(conv.SplitStrToSlice[byte]("48 72 3 250 90 145 217 133 44 170 254 4 180 184 103 164 237 39 160 122 91 238 61 21 7 180 177 135 166 135 119 162", " ")),
			},
			ParachainHeads: types.NewH256(conv.SplitStrToSlice[byte]("232 144 157 221 98 197 55 136 11 32 211 132 52 5 226 140 48 73 161 79 146 109 136 227 220 60 79 176 135 221 18 86", " ")),
		},
	}
	t.Logf("mmrLeaves1: %+v", mmrLeaves1)
	// type MMRBatchProof struct {
	// 	// The index of the leaf the proof is for.
	// 	LeafIndexes []types.U64
	// 	// Number of leaves in MMR, when the proof was generated.
	// 	LeafCount types.U64
	// 	// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
	// 	Items []types.H256
	// }

	beefyProof := beefy.MMRBatchProof{
		LeafIndexes: []types.U64{55},
		LeafCount:   57,
		Items: []types.H256{
			types.NewH256(conv.SplitStrToSlice[byte]("136 207 26 159 194 251 215 234 75 49 198 237 199 224 133 247 125 53 107 197 109 86 76 54 78 105 242 77 79 183 244 80", " ")),
			types.NewH256(conv.SplitStrToSlice[byte]("96 132 170 92 236 117 44 244 176 18 233 162 71 189 214 2 92 249 147 64 214 232 86 146 34 27 176 42 249 21 31 185", " ")),
			types.NewH256(conv.SplitStrToSlice[byte]("49 174 139 205 11 76 243 184 196 172 44 25 173 123 112 78 124 194 201 94 16 127 152 52 221 102 56 53 126 182 211 80", " ")),
			types.NewH256(conv.SplitStrToSlice[byte]("180 66 33 10 54 192 152 46 27 51 60 75 184 81 149 154 170 196 3 134 31 31 238 28 97 110 69 113 63 48 102 139", " ")),
			types.NewH256(conv.SplitStrToSlice[byte]("165 36 244 23 75 4 28 227 24 99 166 189 221 131 165 16 70 68 159 167 198 249 222 194 59 166 176 26 186 15 73 98", " ")),
			types.NewH256(conv.SplitStrToSlice[byte]("167 153 165 242 244 142 157 110 5 49 92 206 138 68 139 27 182 31 218 176 120 16 79 120 42 25 47 121 147 203 117 181", " ")),
		},
	}
	t.Logf("beefyProof: %+v", beefyProof)

	result, err := beefy.VerifyMMRBatchProof(payloadItem[0].Data, mmrSize1,
		mmrLeaves1, beefyProof)
	require.NoError(t, err)
	t.Logf("beefy.VerifyMMRBatchProof --> result: %+v", result)
	// require.True(t, result)

	api, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)

	beefyHeight := commitment.BlockNumber
	// t.Logf("blockNumber: %d", blockNumber)
	beefyHash, err := api.RPC.Chain.GetBlockHash(uint64(beefyHeight))
	require.NoError(t, err)
	t.Logf("beefyHeight: %d beefyHash: %#x", beefyHeight, beefyHash)

	// step2,build beefy mmr
	targetHeights := []uint32{uint32(beefyHeight - 1)}
	// build mmr proofs for leaves containing target paraId
	// mmrBatchProof, err := beefy.BuildMMRBatchProof(localSolochainEndpoint, &latestSignedCommitmentBlockHash, targetHeights)
	mmrBatchProof, err := beefy.BuildMMRProofs(api, targetHeights,
		types.NewOptionU32(types.U32(beefyHeight)),
		types.NewOptionHashEmpty())
	require.NoError(t, err)

	mmrLeaves2 := mmrBatchProof.Leaves
	t.Logf("mmrLeaves2: %+v", mmrLeaves2)
	t.Logf("mmrBatchProof.Proof: %+v", mmrBatchProof.Proof)

	leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(uint32(beefy.BEEFY_ACTIVATION_BLOCK), beefyHeight)
	mmrSize2 := mmr.LeafIndexToMMRSize(uint64(leafIndex))
	t.Logf("mmrSize1: %d <-> mmrSize2: %d", mmrSize1, mmrSize2)
	result, err = beefy.VerifyMMRBatchProof(payloadItem[0].Data, mmrSize2,
		mmrLeaves2, mmrBatchProof.Proof)
	require.NoError(t, err)
	t.Logf("beefy.VerifyMMRBatchProof --> result: %+v", result)
	// require.True(t, result)

}
