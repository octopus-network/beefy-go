package beefy_test

import (
	"context"
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

		t.Logf("skipping since beefy module is not available %v", err)
	}

	// t.Logf("subscribed to %s\n", LOCAL_RELAY_ENDPPOIT)

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
			t.Logf("decoded msg: %#v", s)
			t.Logf("decoded msg: %v", s)
			blockNumber := s.SignedCommitment.Commitment.BlockNumber
			t.Logf("blockNumber: %d", blockNumber)
			blockHash, err := api.RPC.Chain.GetBlockHash(uint64(blockNumber))
			require.NoError(t, err)
			t.Logf("blockHash: %+v", codec.HexEncodeToString(blockHash[:]))

			authorities, err := beefy.GetBeefyAuthorities(blockHash, api, "Authorities")
			require.NoError(t, err)

			authoritySetOnChain, err := beefy.GetBeefyAuthoritySet(blockHash, api, "BeefyAuthorities")
			require.NoError(t, err)
			t.Logf("authoritySetOnChain: %+v", authoritySetOnChain)
			t.Logf("authoritySetOnChain.Root: %#x", authoritySetOnChain.Root)

			bsc := beefy.ConvertCommitment(s.SignedCommitment)
			var authorityIdxes []uint64
			for _, v := range bsc.Signatures {
				idx := v.Index
				authorityIdxes = append(authorityIdxes, uint64(idx))
			}
			authorityMerkleRoot, authorityProof, err := beefy.BuildAuthorityProof(authorities, authorityIdxes)
			require.NoError(t, err)

			// verify signature
			err = beefy.VerifySignature(bsc, uint64(authoritySetOnChain.Len), authorityMerkleRoot, authorityProof)
			require.NoError(t, err)

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
