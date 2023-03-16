package beefy_test

import (
	"strings"
	"testing"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/dablelv/go-huge-util/conv"
	beefy "github.com/octopus-network/beefy-go/beefy"
	"github.com/stretchr/testify/require"
)

func TestConvSlice(t *testing.T) {
	value1 := "115 237 235 146 229 61 38 28 11 196 73 222 20 195 104 74 162 139 133 37 211 117 41 203 7 158 175 254 181 101 87 22 116 217 39 159 111 214 185 199 85 80 62 166 217 178 36 218 53 83 37 138 100 7 169 18 128 57 23 178 111 191 27 245 1"
	t.Logf("Raw value: %#v", value1)
	convValue1 := conv.SplitStrToSlice[byte](value1, " ")
	t.Logf("Split str to uint slice: %v", convValue1)
	t.Logf("Split str to uint slice: %#v", convValue1)
	t.Logf("Split str to uint slice: %+v", convValue1)
	value2 := "190, 171, 181, 52, 208, 35, 61, 63, 243, 167, 41, 72, 146, 79, 19, 208, 223,177, 46, 195, 87, 235, 1, 167, 227, 185, 178, 150, 73, 165, 92, 75"
	t.Logf("Raw value: %v", value2)
	replacedStr := strings.ReplaceAll(value2, ", ", ",")
	t.Logf("replaced value: %v", replacedStr)
	convValue2 := conv.SplitStrToSlice[byte](replacedStr, ",")
	t.Logf("Split str to uint slice: %v", convValue2)

}

func TestLeafIndexAndBlockNumber(t *testing.T) {
	// beefy activate block
	var beefyActivationBlock uint32 = 0

	// the first signed commitment blocknumber
	var signedCommitmentBlockNumber uint32 = 1

	for i := 0; i < 10; i++ {
		leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(beefyActivationBlock, signedCommitmentBlockNumber)
		t.Logf("beefyActivationBlock: %d, signedCommitmentBlockNumber: %d leafIndex: %d", beefyActivationBlock, signedCommitmentBlockNumber, leafIndex)
		signedCommitmentBlockNumber = signedCommitmentBlockNumber + 8
	}

	// if beefyActivationBlock is not 0
	beefyActivationBlock = 88
	// the first signed commitment blocknumber
	signedCommitmentBlockNumber = 89
	for i := 0; i < 10; i++ {
		leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(beefyActivationBlock, signedCommitmentBlockNumber)
		t.Logf("beefyActivationBlock: %d, signedCommitmentBlockNumber: %d leafIndex: %d", beefyActivationBlock, signedCommitmentBlockNumber, leafIndex)
		signedCommitmentBlockNumber = signedCommitmentBlockNumber + 8
	}

}

func TestChainInfo(t *testing.T) {
	// The following example shows how to instantiate a Substrate API and use it to connect to a node
	api, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)

	chain, err := api.RPC.System.Chain()
	require.NoError(t, err)
	t.Log("chain:", chain)

	nodeName, err := api.RPC.System.Name()
	require.NoError(t, err)
	t.Log("nodeName:", nodeName)

	nodeVersion, err := api.RPC.System.Version()
	require.NoError(t, err)
	t.Log("nodeVersion:", nodeVersion)
	t.Logf("You are connected to chain %v using %v v%v\n", chain, nodeName, nodeVersion)

	rpcMethods, err := beefy.RpcMethods(api)
	require.NoError(t, err)
	methods := rpcMethods.Methods
	t.Logf("rpc methods:")
	for _, m := range methods {
		t.Logf("%s", m)
	}
	

}
