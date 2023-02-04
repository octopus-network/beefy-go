package beefy_test

import (
	"context"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/merkle"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"

	// "github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/stretchr/testify/assert"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types"

	beefy "github.com/octopus-network/beefy-go"
	"github.com/stretchr/testify/require"
)

var endpoint = "wss://rococo-rpc.polkadot.io"

func TestBeefyAuthoritySetCodec(t *testing.T) {
	var validatorSet1 = types.BeefyNextAuthoritySet{
		ID:   6222,
		Len:  83,
		Root: [32]byte{242, 71, 234, 49, 93, 55, 186, 220, 142, 244, 51, 94, 85, 241, 146, 62, 213, 162, 250, 37, 110, 101, 244, 99, 128, 6, 194, 124, 44, 64, 44, 140},
	}
	encodeData, err := codec.Encode(validatorSet1)
	require.NoError(t, err)
	log.Printf("encoded validatorSet : %#v\n", codec.HexEncodeToString(encodeData[:]))

	var validatorSet2 types.BeefyNextAuthoritySet

	err = codec.Decode(encodeData, &validatorSet2)

	if err != nil {
		log.Printf("decode err: %#s\n", err)
	}
	log.Printf("decoded validatorSet: %#v\n", validatorSet2)

}

func TestVerifyValidatorProof(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(endpoint)
	if err != nil {
		// fmt.Printf("connection err,%s", err)
		log.Printf("Connecting err: %v", err)
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
		// log.Printf("skipping since beefy module is not available %v", err)
	}

	// fmt.Printf("subscribed to %s\n", polkadot_endpoint)
	log.Printf("subscribed to %s\n", endpoint)
	// assert.NoError(t, err)
	defer sub.Unsubscribe()

	timeout := time.After(24 * time.Hour)
	received := 0

	for {
		select {
		case msg := <-ch:
			log.Printf("encoded msg: %s\n", msg)

			// s := &types.SignedCommitment{}
			s := &beefy.VersionedFinalityProof{}
			err := codec.DecodeFromHex(msg.(string), s)
			if err != nil {
				panic(err)
			}

			log.Printf("encoded msg: %#v\n", s)
			blockNumber := s.SignedCommitment.Commitment.BlockNumber
			log.Printf("blockNumber: %d\n", blockNumber)
			blockHash, err := api.RPC.Chain.GetBlockHash(uint64(blockNumber))
			require.NoError(t, err)
			log.Printf("blockHash: %#v\n", codec.HexEncodeToString(blockHash[:]))
			authorities, err := beefy.GetBeefyAuthorities(blockHash, api, "Authorities")
			require.NoError(t, err)
			// log.Printf("authorities: %#v\n", authorities)
			var authorityLeaves [][]byte
			for _, v := range authorities {
				authorityLeaves = append(authorityLeaves, crypto.Keccak256(v))
			}
			authorityTree, err := merkle.NewTree(hasher.Keccak256Hasher{}).FromLeaves(authorityLeaves)
			require.NoError(t, err)
			var authorityTreeRoot = beefy.Bytes32(authorityTree.Root())
			log.Printf("authorityTreeRoot: %#v\n", codec.HexEncodeToString(authorityTreeRoot[:]))
			createBeefyAuthoritySet := beefy.BeefyAuthoritySet{
				Id:            uint64(s.SignedCommitment.Commitment.ValidatorSetID),
				Len:           uint32(len(authorities)),
				AuthorityRoot: &authorityTreeRoot,
			}
			log.Printf("created authorityTreeRoot: %#v\n", createBeefyAuthoritySet)
			statedBeefyAuthoritySetBytes, err := beefy.GetBeefyAuthoritySet(blockHash, api, "BeefyAuthorities")
			require.NoError(t, err)
			log.Printf("statedBeefyAuthoritySetBytes: %#v\n", statedBeefyAuthoritySetBytes)

			csc, proofs, err := beefy.CreateAuthorityProof(s.SignedCommitment, authorityTree)
			require.NoError(t, err)
			err = beefy.VerifyAuthoritySignatures(csc, createBeefyAuthoritySet, proofs, authorityTreeRoot)
			require.NoError(t, err)

			received++

			if received >= 10 {
				return
			}
		case <-timeout:
			log.Printf("timeout reached without getting 2 notifications from subscription")
			return
		}
	}
}
