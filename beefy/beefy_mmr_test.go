package beefy_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/mmr"
	merkletypes "github.com/ComposableFi/go-merkle-trees/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/ethereum/go-ethereum/crypto"
	beefy "github.com/octopus-network/beefy-go/beefy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// var beefyActivationBlock = 0

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
	leafIndex := beefy.GetLeafIndexForBlockNumber(0, blockNumber)
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

func TestBuildMMRBatchProof(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	// block hash 0x2c0eedbd6e05507f7177509d717a46195c14f8659abb6756054d406ac2656970
	// blockHash, err := codec.HexDecodeString("0x2c0eedbd6e05507f7177509d717a46195c14f8659abb6756054d406ac2656970")
	hexStr := "0x2c0eedbd6e05507f7177509d717a46195c14f8659abb6756054d406ac2656970"
	require.NoError(t, err)
	idxes := []uint64{3014, 3016, 3018, 3020}
	blockHash, err := types.NewHashFromHexString(hexStr)
	require.NoError(t, err)
	batchProof, err := beefy.BuildMMRBatchProof(api, &blockHash, idxes)
	require.NoError(t, err)
	t.Logf("BuildMMRBatchProof: %+v", batchProof)
}

func TestBuildAndVerifyMMRProofLocal(t *testing.T) {
	encodeVersionedFinalityProof := "0x01046d688092f9d4139eed1e8e02af86f31b70877a80c22f2eb52707e07b6e787b7bdc27506f120000d70100000000000004e80500000010a195e47c9ad10b666cd7c155cacfdd502e14af049957b10213c5c671bc433dff30dcf7cf7b4b7a34bb9249676a33876f719ec92fcbd04b1c99e240705b1513f801d8edd31f6ba7cd207f94422454584f4f00ab190ebec1176b3be56544f349d8145468c3da686d3bc148c7576ce33be5b1ad913814da4af659c825cc4f4d829186003907980301b9c7415df46824b99da4fb3aa55c55f814bcc17e139ffff1b8469f0edf4b27b8eadbc68e7ebf6f0f0bcd36a159333c89422f7c074db01f0382aefe01bfacc658e45c1950dc4e96ea40b7b5a890b238edebce6b7e56876d5fae49659e6b345e51036a851b40d180884ea0fd68d32896ff3acf9d3f7085a5cedaa57e5e00"
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
	leafIndex := beefy.GetLeafIndexForBlockNumber(0, blockNumber)
	t.Logf("leafIndex: %d", leafIndex)

	api, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	// blockHash := "0x729d5e86a4ec7ad0a5f7fa18357256c3c1c110407be4164dcf88ec33c2b4ed98"
	blockHash, err := api.RPC.Chain.GetBlockHash(uint64(blockNumber))
	require.NoError(t, err)
	t.Logf("bockHash: %#x", blockHash)

	// retBlockHash, mmrLeaf, mmrLeafProof, err := beefy.BuildMMRProof(api, leafIndex, blockHash)
	retBlockHash, mmrLeaf, mmrLeafProof, err := beefy.BuildMMRProof(api, uint64(blockNumber), blockHash)
	require.NoError(t, err)
	t.Logf("\nrethash: %#x\nmmrLeaf: %+v\nmmrLeafProof: %+v", retBlockHash, mmrLeaf, mmrLeafProof)
	// mmrSize := mmr.LeafIndexToMMRSize(leafIndex)
	mmrSize := mmr.LeafIndexToMMRSize(leafIndex + 1)
	t.Logf("mmrSize:%d\n ", mmrSize)
	result, err := beefy.VerifyMMRProof(decodedVersionedFinalityProof.SignedCommitment, mmrSize, leafIndex, mmrLeaf, mmrLeafProof)
	require.NoError(t, err)
	t.Logf("verify mmr proof result: %#v", result)

}

func TestVerifyMMRLocal(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
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

	t.Logf("subscribed to %s\n", LOCAL_RELAY_ENDPPOIT)
	// assert.NoError(t, err)
	defer sub.Unsubscribe()

	timeout := time.After(24 * time.Hour)
	received := 0

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
			blockNumber := s.SignedCommitment.Commitment.BlockNumber
			// t.Logf("blockNumber: %d", blockNumber)
			blockHash, err := api.RPC.Chain.GetBlockHash(uint64(blockNumber))
			require.NoError(t, err)
			t.Logf("blockHash: %#v", codec.HexEncodeToString(blockHash[:]))
			leafIndex := beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), blockNumber)
			mmrSize := mmr.LeafIndexToMMRSize(leafIndex)

			// t.Logf("mmrSize:%d\n ", mmrSize)
			// retHash, mmrLeaf, mmrLeafProof, err := beefy.BuildMMRProof(api, leafIndex, blockHash)
			retHash, mmrLeaf, mmrLeafProof, err := beefy.BuildMMRProof(api, uint64(blockNumber), blockHash)
			t.Logf("blockNumber: %d leafIndex: %d mmrSize:%d", blockNumber, leafIndex, mmrSize)
			require.NoError(t, err)
			t.Logf("\nrethash: %#x\nmmrLeaf: %+v\nmmrLeafProof: %+v", retHash, mmrLeaf, mmrLeafProof)

			result, err := beefy.VerifyMMRProof(s.SignedCommitment, mmrSize, leafIndex, mmrLeaf, mmrLeafProof)
			require.NoError(t, err)
			t.Logf("verify mmr proof result: %#v", result)

			received++

			if received >= 10 {
				return
			}
		case <-timeout:
			t.Logf("timeout reached without getting 2 notifications from subscription")
			return
		}
	}
}
