package beefy_test

import (
	"context"
	"testing"
	"time"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	beefy "github.com/octopus-network/beefy-go/beefy"
	"github.com/stretchr/testify/require"
)

func TestSignedCommitmentCodec(t *testing.T) {
	encodeMsg := "0x01046d6880c77609e63a1ab85353fd89c7c1ca3fa91e3c593bdb936eacaf2e8e3dcbb7648b73100000a50100000000000004d8050000001073edeb92e53d261c0bc449de14c3684aa28b8525d37529cb079eaffeb565571674d9279f6fd6b9c755503ea6d9b224da3553258a6407a912803917b26fbf1bf50168ab224e58c8408b470e5798bca58543677599d030ce4403cf6595fe96c734f71ed1907f54f64f724ecccc4722499939a3b213df603edafa52a5cb824050345a000fb0f5230d56ce68f4d53c2b8d85f272099d471f2a6c5b5418c2f08dd77ecb6d731626715437ee53d0abd4573af923ee92916e1b7c2bb5e5d3a661545dc378d6007d65cd2adb3b25e19e7848daeb4eb64ef1415be1aba2744e30979c791fdb908913018b3f52cbd95a460b19d34d1ecb94c0ad1d3ffe5b3960206a4716efdc010601"
	t.Log("encoded SignedCommitment: ", encodeMsg)
	decodedMsg := &beefy.VersionedFinalityProof{}
	err := codec.DecodeFromHex(encodeMsg, decodedMsg)
	require.NoError(t, err)
	t.Logf("decoded SignedCommitment: %+v", decodedMsg)
	reEncodeMsg, err := codec.Encode(decodedMsg)
	require.NoError(t, err)
	t.Logf("reEncode SignedCommitment: %#x", reEncodeMsg)
	require.Equal(t, encodeMsg, codec.HexEncodeToString(reEncodeMsg))
	// jsonMsg, err := hug_encoding.ToIndentJSON(decodedMsg)
	// require.NoError(t, err)
	// t.Logf("SignedCommitment json: %s", jsonMsg)

}

func TestVerifySignedCommitmentLocal(t *testing.T) {
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
	// var beefyActivationBlock uint32 = 1

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
			blockNumber := s.SignedCommitment.Commitment.BlockNumber
			t.Logf("blockNumber: %d\n", blockNumber)
			blockHash, err := api.RPC.Chain.GetBlockHash(uint64(blockNumber))
			require.NoError(t, err)
			t.Logf("blockHash: %#x", blockHash)
			leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(beefy.BEEFY_ACTIVATION_BLOCK, blockNumber)
			t.Logf("blockNumber: %d leafIndex: %d", blockNumber, leafIndex)
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
