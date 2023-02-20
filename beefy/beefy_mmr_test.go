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

//TODO: use static data to test
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
			targetBlockNumber := singedCommitmentblockNumber - 5
			// leafIndex := beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), singedCommitmentblockNumber)
			leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(uint32(beefy.BEEFY_ACTIVATION_BLOCK), targetBlockNumber)

			// t.Logf("mmrSize:%d\n ", mmrSize)
			// retHash, mmrLeaf, proof, err := beefy.BuildMMRProof(api, leafIndex, blockHash)
			// Note: get the mmr proof for target block number,must input target block number ,do not input LeafIndex
			retHash, mmrLeaf, proof, err := beefy.BuildMMRProof(relayApi, uint64(targetBlockNumber), singedCommitmentBlockHash)

			leafCount := proof.LeafCount
			// parachainHeadsMerkleRoot := mmrLeaf.ParachainHeads
			mmrSize1 := mmr.LeafIndexToMMRSize(leafIndex)
			mmrSize2 := mmr.LeafIndexToMMRSize(uint64(leafCount))

			var mmrLeafProof = make([][]byte, len(proof.Items))
			for i := 0; i < len(proof.Items); i++ {
				mmrLeafProof[i] = proof.Items[i][:]
			}

			t.Logf("singedCommitmentblockNumber:%d targetBlockNumber:%d leafIndex:%d proof.LeafIndex:%d leafCount:%d mmrSize1:%d mmrSize2:%d",
				singedCommitmentblockNumber, targetBlockNumber, leafIndex, proof.LeafIndex, leafCount, mmrSize1, mmrSize2)
			require.NoError(t, err)
			t.Logf("\nrethash: %#x\nmmrLeaf: %+v\nmmrLeafProof: %+v", retHash, mmrLeaf, mmrLeafProof)

			// step1: verfiy relayer chain mmr proof
			// result1, err := beefy.VerifyMMRProof(s.SignedCommitment, mmrSize1, leafIndex, mmrLeaf, mmrLeafProof)
			// require.NoError(t, err)
			// t.Logf("verify mmr proof result: %#v", result1)
			t.Log("--- Begin to verify relayer chain mmr proof ---")
			result2, err := beefy.VerifyMMRProof(s.SignedCommitment.Commitment, mmrSize2, leafIndex, mmrLeaf, mmrLeafProof)
			require.NoError(t, err)
			t.Logf("verify mmr proof result: %#v", result2)
			t.Log("--- End to verify relayer chain mmr proof --- \n")

			// step2: verify parachain header at target height
			// get target block hash
			t.Log("--- Begin to verify relayer chain header ---")
			targetBlockHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(targetBlockNumber))
			require.NoError(t, err)
			t.Logf("targetBlockNumber: %d targetBlockHash: %#x", targetBlockNumber, targetBlockHash)
			targetRelayerHeader, err := relayApi.RPC.Chain.GetHeader(targetBlockHash)
			require.NoError(t, err)
			t.Logf("targetBlockHash: %#x\n targetRelayerHeader: %+v", targetBlockHash, targetRelayerHeader)
			t.Logf("targetRelayerHeader.ParentHash: %#x", targetRelayerHeader.ParentHash)
			t.Logf("mmrLeaf.ParentNumberAndHash.Hash: %#x", mmrLeaf.ParentNumberAndHash.Hash)
			t.Log("--- End to verify relayer chain header --- \n")

			// step3: verify parachain header at target height
			t.Log("--- Begin to verify para chain header ---")
			targetEncodedParaHeader, err := beefy.GetParachainHeader(relayApi, uint32(beefy.LOCAL_PARACHAIN_ID), targetBlockHash)
			// It`s possobile there is not parachain header at target height
			require.NoError(t, err)
			t.Logf("targetBlockHash: %#x\n targetParaHeader: %#x", targetBlockHash, targetEncodedParaHeader)
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
			targetParaHeaderStateProof, err := beefy.GetParachainHeaderProof(relayApi, targetBlockHash, beefy.LOCAL_PARACHAIN_ID)
			require.NoError(t, err)
			t.Logf("targetParaHeaderStateProof: %+v", targetParaHeaderStateProof)
			paraHeaderStateproofs := make([][]byte, len(targetParaHeaderStateProof.Proof))
			for _, proof := range targetParaHeaderStateProof.Proof {
				paraHeaderStateproofs = append(paraHeaderStateproofs, proof[:])
			}

			relayerHeaderStateTrieProof, err := trie_proof.BuildTrie(paraHeaderStateproofs, targetRelayerHeader.StateRoot[:])
			t.Log("relayer chain Header Trie proof:\n", relayerHeaderStateTrieProof)
			require.NoError(t, err)

			meta, err := relayApi.RPC.State.GetMetadataLatest()
			require.NoError(t, err)
			paraIdEncoded := make([]byte, 4)
			binary.LittleEndian.PutUint32(paraIdEncoded, beefy.LOCAL_PARACHAIN_ID)
			targetParaHeaderKey, err := types.CreateStorageKey(meta, "Paras", "Heads", paraIdEncoded)
			require.NoError(t, err)
			log.Printf("targetParaHeaderKey: %#x", targetParaHeaderKey)
			// find the parachain header
			paraHeaderValue := relayerHeaderStateTrieProof.Get(targetParaHeaderKey)
			require.NotEmpty(t, paraHeaderValue)
			t.Logf("The targetParaHeader value from trie proof: %#x", paraHeaderValue)
			// decode the target para chain header
			// var targetParaHeader = substrate.NewEmptyHeader()
			// err = trie_scale.Unmarshal(paraHeaderValue, &targetParaHeader)
			// require.NoError(t, err)
			// t.Logf("targetParaHeader: %+v", targetParaHeader)

			// err = trie_proof.Verify(paraHeaderStateproofs, targetRelayerHeader.StateRoot[:], targetParaHeaderKey, paraHeaderValue)
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
			// t.Logf("timestamp from parachain: ", timestamp)
			t.Logf("timestamp from parachain: %d hex: %x", timestamp, timestamp)
			time_str := time.UnixMilli(int64(timestamp))
			t.Logf("timestamp from parachain: %s", time_str)

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
			if received >= 5 {
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
	// block hash 0x2c0eedbd6e05507f7177509d717a46195c14f8659abb6756054d406ac2656970
	// blockHash, err := codec.HexDecodeString("0x2c0eedbd6e05507f7177509d717a46195c14f8659abb6756054d406ac2656970")
	// hexStr := "0x2c0eedbd6e05507f7177509d717a46195c14f8659abb6756054d406ac2656970"
	// blockHash, err := types.NewHashFromHexString(hexStr)
	blockHash, err := api.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	header, err := api.RPC.Chain.GetHeader(blockHash)
	require.NoError(t, err)
	t.Logf("header: %+v", header)
	// require.NoError(t, err)
	// t.Logf("blockHash: %#x", blockHash)
	idxes := []uint64{uint64(header.Number) - 6, uint64(header.Number) - 4, uint64(header.Number) - 2}
	t.Logf("idxes: %+v", idxes)
	require.NoError(t, err)
	batchProof, err := beefy.BuildMMRBatchProof(api, &blockHash, idxes)
	require.NoError(t, err)
	t.Logf("BuildMMRBatchProof: %+v", batchProof)
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
			t.Logf("latestSignedCommitmentBlockNumber: %d latestSignedCommitmentBlockHash: %#x", latestSignedCommitmentBlockNumber, latestSignedCommitmentBlockHash)

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
			var targetRelayChainBlockHeights []uint64
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
				targetRelayChainBlockHeights = append(targetRelayChainBlockHeights, uint64(header.Number))

			}

			// build mmr proofs for leaves containing target paraId
			mmrBatchProof, err := beefy.BuildMMRBatchProof(api, &latestSignedCommitmentBlockHash, targetRelayChainBlockHeights)
			require.NoError(t, err)
			// t.Logf("mmrBatchProof: %+v", mmrBatchProof)
			t.Logf("mmrBatchProof.BlockHash: %#x", mmrBatchProof.BlockHash)
			t.Logf("mmrBatchProof leaves len: %d", len(mmrBatchProof.Leaves))
			for _, leaf := range mmrBatchProof.Leaves {
				t.Logf("mmrBatchProof leaf: %+v", leaf)
			}
			t.Logf("targetRelayChainBlockHeights: %+v", targetRelayChainBlockHeights)
			t.Logf("The indexes of the leaf the proof is for: %+v", mmrBatchProof.Proof.LeafIndex)
			t.Logf("Number of leaves in MMR, when the proof was generated: %d", mmrBatchProof.Proof.LeafCount)
			// leafCount := mmrBatchProof.Proof.LeafCount
			// mmrSize := mmr.LeafIndexToMMRSize(uint64(leafCount))
			leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(uint32(beefy.BEEFY_ACTIVATION_BLOCK), latestSignedCommitmentBlockNumber)
			mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
			t.Logf("beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), latestSignedCommitmentBlockNumber): %d", leafIndex)
			t.Logf("mmr.LeafIndexToMMRSize(uint64(leafIndex)): %d", mmrSize)

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
					Index: uint64(mmrBatchProof.Proof.LeafIndex[i]),
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
			result, err := beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload[0], mmrSize,
				mmrBatchProof.Leaves, mmrBatchProof.Proof)
			require.NoError(t, err)
			t.Logf("beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload[0], mmrSize,mmrBatchProof.Leaves, mmrBatchProof.Proof) result: %+v", result)
			require.True(t, result)

			// save latestSignedCommitment for next verify
			preBlockNumber = latestSignedCommitmentBlockNumber
			preBloackHash = latestSignedCommitmentBlockHash

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
