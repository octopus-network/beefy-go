package beefy_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	hug_encoding "github.com/dablelv/go-huge-util/encoding"
	beefy "github.com/octopus-network/beefy-go/beefy"

	"github.com/stretchr/testify/assert"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"

	"github.com/stretchr/testify/require"
)

func TestBeefyAuthoritySetCodec(t *testing.T) {
	var validatorSet1 = types.BeefyNextAuthoritySet{
		ID:   6222,
		Len:  83,
		Root: [32]byte{242, 71, 234, 49, 93, 55, 186, 220, 142, 244, 51, 94, 85, 241, 146, 62, 213, 162, 250, 37, 110, 101, 244, 99, 128, 6, 194, 124, 44, 64, 44, 140},
	}
	encodeData, err := codec.Encode(validatorSet1)
	require.NoError(t, err)
	t.Logf("encoded validatorSet : %+v", codec.HexEncodeToString(encodeData[:]))

	var validatorSet2 types.BeefyNextAuthoritySet

	err = codec.Decode(encodeData, &validatorSet2)

	if err != nil {
		t.Logf("decode err: %#s\n", err)
	}
	t.Logf("decoded validatorSet: %+v", validatorSet2)

	jsonMsg, err := hug_encoding.ToIndentJSON(validatorSet2)
	require.NoError(t, err)
	t.Logf("validatorSet json: %s", jsonMsg)

}

func TestVerifyValidatorProofLocal(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
	if err != nil {
		// fmt.Printf("connection err,%s", err)
		t.Logf("Connecting err: %v", err)
		// t.Log("Connecting err: %v", err)
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
		fmt.Printf("skipping since beefy module is not available")
		// t.Logf("skipping since beefy module is not available %v", err)
	}

	// fmt.Printf("subscribed to %s\n", polkadot_endpoint)
	t.Logf("subscribed to %s\n", LOCAL_RELAY_ENDPPOIT)
	// assert.NoError(t, err)
	defer sub.Unsubscribe()

	timeout := time.After(24 * time.Hour)
	received := 0

	for {
		select {
		case msg := <-ch:
			t.Logf("encoded msg: %s", msg)

			// s := &types.SignedCommitment{}
			s := &beefy.VersionedFinalityProof{}
			err := codec.DecodeFromHex(msg.(string), s)
			if err != nil {
				panic(err)
			}

			t.Logf("decoded msg: %+v", s)
			blockNumber := s.SignedCommitment.Commitment.BlockNumber
			t.Logf("blockNumber: %d", blockNumber)
			blockHash, err := api.RPC.Chain.GetBlockHash(uint64(blockNumber))
			require.NoError(t, err)
			t.Logf("blockHash: %+v", codec.HexEncodeToString(blockHash[:]))

			authorities, err := beefy.GetBeefyAuthorities(blockHash, api, "Authorities")
			require.NoError(t, err)
			// t.Logf("authorities: %#v\n", authorities)
			// var authorityLeaves [][]byte
			// for _, v := range authorities {
			// 	authorityLeaves = append(authorityLeaves, crypto.Keccak256(v))
			// }
			// authorityTree, err := merkle.NewTree(hasher.Keccak256Hasher{}).FromLeaves(authorityLeaves)
			// require.NoError(t, err)
			// var authorityTreeRoot = beefy.Bytes32(authorityTree.Root())
			// // var authorityTreeRoot = authorityTree.Root()
			// t.Logf("authorityTreeRoot: %+v", codec.HexEncodeToString(authorityTreeRoot[:]))
			// currentBeefyAuthoritySet := beefy.BeefyAuthoritySet{
			// 	Id:   uint64(s.SignedCommitment.Commitment.ValidatorSetID),
			// 	Len:  uint32(len(authorities)),
			// 	Root: authorityTreeRoot,
			// }
			// t.Logf("created authorityTreeRoot: %+v", currentBeefyAuthoritySet)

			statedBeefyAuthoritySetBytes, err := beefy.GetBeefyAuthoritySet(blockHash, api, "BeefyAuthorities")
			require.NoError(t, err)
			t.Logf("statedBeefyAuthoritySetBytes: %+v", statedBeefyAuthoritySetBytes)

			csc := beefy.ConvertCommitment(s.SignedCommitment)
			var authorityIdxes []uint64
			for _, v := range csc.Signatures {
				idx := v.AuthorityIndex
				authorityIdxes = append(authorityIdxes, uint64(idx))
			}
			authorityTreeRoot, authorityProofs, err := beefy.BuildAuthorityProofs(authorities, authorityIdxes)
			require.NoError(t, err)
			err = beefy.VerifyCommitmentSignatures(csc, uint64(statedBeefyAuthoritySetBytes.Len), authorityTreeRoot, authorityProofs)
			require.NoError(t, err)

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
