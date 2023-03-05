package beefy_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"sort"
	"testing"
	"time"

	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/merkle"
	"github.com/ComposableFi/go-merkle-trees/mmr"
	merkletypes "github.com/ComposableFi/go-merkle-trees/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/hash"
	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/octopus-network/beefy-go/beefy"

	// substrateTypes "github.com/octopus-network/trie-go/substrate"
	"github.com/stretchr/testify/require"
)

func TestDecodeParachainHeader(t *testing.T) {
	headerBytes, err := hex.DecodeString("7edf044b273544342c4dc30a234c327405b3b03f2f20f53fc6a41d6d2765536d38efc4d9b628f9ddb17b542822e3df456b5431c62a005a67bb593d30da23f2e57581004e468f3616573199929694b06fc4248c449621f1e04b7c1dc3135bc1f6e9080642414245340200000000bdaca9200000000005424142450101b4061c25a6260134de85942c551d75d7e29e660a8b090a4ec08051b32dad7253e7536a1214d06648c865a44a10ffd7a457f8d62c5783b55fd29d0faa1912c885")
	require.NoError(t, err, "error decoding parachain bytes")

	var header types.Header
	err = codec.Decode(headerBytes, &header)
	require.NoError(t, err, "error decoding parachain header")

	parentHash, err := hex.DecodeString("7edf044b273544342c4dc30a234c327405b3b03f2f20f53fc6a41d6d2765536d")
	require.NoError(t, err)

	require.Equal(t, header.ParentHash[:], parentHash[:], "error comparing decoded parent hash")

	extrinsicsRoot, err := hex.DecodeString("81004e468f3616573199929694b06fc4248c449621f1e04b7c1dc3135bc1f6e9")
	require.NoError(t, err)

	require.Equal(t, header.ExtrinsicsRoot[:], extrinsicsRoot[:], "error comparing extrinsicsRoot")

	stateRoot, err := hex.DecodeString("efc4d9b628f9ddb17b542822e3df456b5431c62a005a67bb593d30da23f2e575")
	require.NoError(t, err)

	require.Equal(t, header.StateRoot[:], stateRoot[:], "error comparing StateRoot")

	require.Equal(t, types.BlockNumber(types.NewU32(14)), header.Number, "failed to check block number from decoded header")

}

func TestDecodeExtrinsicTimestamp(t *testing.T) {
	var timeUnix uint64 = 1643972151006
	timestampBytes, err := hex.DecodeString("280403000bde4660c47e01")
	require.NoError(t, err)
	// timestampStr := time.UnixMilli(timeUnix)
	// time_str := time.Unix(int64(timestamp), 0)
	t.Logf("cal timestamp from trie proof: %s", time.UnixMilli(int64(timeUnix)))
	var extrinsic types.Extrinsic
	err = codec.Decode(timestampBytes, &extrinsic)
	require.NoError(t, err)
	t.Logf("extrinsic: %+v", extrinsic)
	unixTimeFromExtrinsic, err := scale.NewDecoder(bytes.NewReader(extrinsic.Method.Args[:])).DecodeUintCompact()
	require.NoError(t, err)

	t.Logf("unix time decoded from extrinsic: %s", time.UnixMilli(int64(unixTimeFromExtrinsic.Uint64())))
	t.Logf("unix time decoded from extrinsic: %d expected timestamp: %d", unixTimeFromExtrinsic.Uint64(), timeUnix)
	require.Equal(t, timeUnix, unixTimeFromExtrinsic.Uint64(), "failed to decode unix timestamp")

}
func TestGetParachainInfoLive(t *testing.T) {

	//local testnet
	local, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	blockHash, err := local.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	paraChainIds, err := beefy.GetParachainIds(local, blockHash)
	require.NoError(t, err)
	t.Logf("paraChainIds: %+v", paraChainIds)
	for _, paraChainId := range paraChainIds {
		t.Logf("paraChainId: %d", paraChainId)
		paraChainHeader, err := beefy.GetParachainHeader(local, uint32(paraChainId), blockHash)
		require.NoError(t, err)
		t.Logf("paraChainHeader: %#x", paraChainHeader)
	}

	// rococo  testnet
	rococo, err := gsrpc.NewSubstrateAPI(beefy.ROCOCO_ENDPOIN)
	require.NoError(t, err)
	blockHash, err = rococo.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	paraChainIds, err = beefy.GetParachainIds(rococo, blockHash)
	require.NoError(t, err)
	t.Logf("paraChainIds: %+v", paraChainIds)
	for _, paraChainId := range paraChainIds {
		t.Logf("paraChainId: %d", paraChainId)
		paraChainHeader, err := beefy.GetParachainHeader(rococo, uint32(paraChainId), blockHash)
		require.NoError(t, err)
		t.Logf("paraChainHeader: %#x", paraChainHeader)
		var decodeParachainHeader types.Header
		err = codec.Decode(paraChainHeader, &decodeParachainHeader)
		require.NoError(t, err)
		t.Logf("decodeParachainHeader: %+v", decodeParachainHeader)
	}

	// polkadot mainnet
	polkadot, err := gsrpc.NewSubstrateAPI(beefy.ROCOCO_ENDPOIN)
	require.NoError(t, err)
	blockHash, err = polkadot.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	paraChainIds, err = beefy.GetParachainIds(polkadot, blockHash)
	require.NoError(t, err)
	t.Logf("paraChainIds: %+v", paraChainIds)
	for _, paraChainId := range paraChainIds {
		t.Logf("paraChainId: %d", paraChainId)
		paraChainHeader, err := beefy.GetParachainHeader(polkadot, uint32(paraChainId), blockHash)
		require.NoError(t, err)
		t.Logf("paraChainHeader: %#x", paraChainHeader)
		var decodeParachainHeader types.Header
		err = codec.Decode(paraChainHeader, &decodeParachainHeader)
		require.NoError(t, err)
		t.Logf("decodeParachainHeader: %+v", decodeParachainHeader)
	}
}

func TestQueryParachainStorageLocal(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)

	latestFinalizedHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	// t.Logf("latestFinalizedHash: %#x", latestFinalizedHash)
	latestFinalizedHeader, err := relayApi.RPC.Chain.GetHeader(latestFinalizedHash)
	// endFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(endBlockNumber))
	require.NoError(t, err)
	t.Logf("latestFinalizedHeader: %+v", latestFinalizedHeader)

	toBlockNumber := latestFinalizedHeader.Number

	fromBlockNumber := toBlockNumber - 7
	t.Logf("fromBlockNumber: %d toBlockNumber: %d", fromBlockNumber, toBlockNumber)

	fromFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(fromBlockNumber))
	require.NoError(t, err)
	t.Logf("fromBlockHash: %#x ", fromFinalizedHash)
	// t.Logf("toBlockNumber: %d", toBlockNumber)
	t.Logf("toBlockHash: %#x", latestFinalizedHash)

	changeSets, err := beefy.QueryParachainStorage(relayApi, beefy.LOCAL_PARACHAIN_ID, fromFinalizedHash, latestFinalizedHash)
	require.NoError(t, err)
	t.Logf("changeSet len: %d", len(changeSets))
	for _, changeSet := range changeSets {
		header, err := relayApi.RPC.Chain.GetHeader(changeSet.Block)
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

	}

}

func TestQueryStorageRococo(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.ROCOCO_ENDPOIN)
	require.NoError(t, err)

	var startBlockNumber = 3707562
	t.Logf("startBlockNumber: %d", startBlockNumber)
	t.Logf("startBlockNumber+1: %d", startBlockNumber+1)
	startFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(startBlockNumber + 1))
	require.NoError(t, err)
	t.Logf("startFinalizedHash: %#x", startFinalizedHash)

	var endBlockNumber = 3707570
	t.Logf("endBlockNumber: %d", endBlockNumber)
	endFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(endBlockNumber))
	require.NoError(t, err)
	t.Logf("endBlockNumber: %#x", endFinalizedHash)

	var paraHeaderKeys []types.StorageKey

	// create full storage key for our own paraId
	keyPrefix := beefy.CreateStorageKeyPrefix("Paras", "Heads")
	t.Logf("keyPrefix: %s", codec.HexEncodeToString(keyPrefix[:]))
	// so we can query all blocks from lastfinalized to latestBeefyHeight
	t.Logf("ROCOCO_PARACHAIN_ID: %d", beefy.ROCOCO_ROCKMIN_ID)
	encodedParaID, err := codec.Encode(beefy.ROCOCO_ROCKMIN_ID)
	t.Logf("encodedParaID: %#x", encodedParaID)
	require.NoError(t, err)

	twoXHash := xxhash.New64(encodedParaID).Sum(nil)
	t.Logf("encodedParaID twoXHash: %#x", twoXHash)
	// full key path in the storage source: https://www.shawntabrizi.com/assets/presentations/substrate-storage-deep-dive.pdf
	// xx128("Paras") + xx128("Heads") + xx64(Encode(paraId)) + Encode(paraId)
	fullKey := append(append(keyPrefix, twoXHash[:]...), encodedParaID...)
	t.Logf("fullKey: %#x", fullKey)
	paraHeaderKeys = append(paraHeaderKeys, fullKey)

	var changSet []types.StorageChangeSet

	for i := startBlockNumber + 1; i <= endBlockNumber; i++ {
		blockHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(i))
		t.Logf("blockHash: %#x", blockHash)
		require.NoError(t, err)
		cs, err := relayApi.RPC.State.QueryStorageAt(paraHeaderKeys, blockHash)
		require.NoError(t, err)
		t.Logf("cs: %+v", cs)
		changSet = append(changSet, cs...)
		// t.Logf("changeSet: %#v", changeSet)

	}
	t.Logf("changeSet: %+v", changSet)
}

func TestBuildRelayerHeaderMapLocal(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)

	latestFinalizedHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	// t.Logf("latestFinalizedHash: %#x", latestFinalizedHash)
	latestFinalizedHeader, err := relayApi.RPC.Chain.GetHeader(latestFinalizedHash)
	// endFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(endBlockNumber))
	require.NoError(t, err)
	t.Logf("latestFinalizedHeader: %+v", latestFinalizedHeader)

	toBlockNumber := latestFinalizedHeader.Number

	fromBlockNumber := toBlockNumber - 7
	t.Logf("fromBlockNumber: %d toBlockNumber: %d", fromBlockNumber, toBlockNumber)

	fromFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(fromBlockNumber))
	require.NoError(t, err)
	t.Logf("fromBlockHash: %#x ", fromFinalizedHash)
	// t.Logf("toBlockNumber: %d", toBlockNumber)
	t.Logf("toBlockHash: %#x", latestFinalizedHash)

	changeSets, err := beefy.QueryParachainStorage(relayApi, beefy.LOCAL_PARACHAIN_ID, fromFinalizedHash, latestFinalizedHash)
	require.NoError(t, err)
	t.Logf("changeSet len: %d", len(changeSets))
	for _, changeSet := range changeSets {
		header, err := relayApi.RPC.Chain.GetHeader(changeSet.Block)
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

	}

	relayerHeaderMap, relayChainHeaderIdxes, err := beefy.BuildRelaychainHeaderMap(relayApi, latestFinalizedHash, changeSets)
	require.NoError(t, err)
	t.Logf("relayerHeaderMap len: %d", len(relayerHeaderMap))
	t.Logf("relayChainHeaderIdxes: %+v", relayChainHeaderIdxes)
	// t.Logf("relayerHeaderMap: %+v", relayerHeaderMap)
	for number, parachainMap := range relayerHeaderMap {
		t.Logf("relayerHeaderMap at block: %d includes parachain header count: %d", number, len(parachainMap))
		// t.Logf("parachainHeader len: %d", )
		for pardId, parachainHeader := range parachainMap {
			t.Logf("parachain id: %d", pardId)
			t.Logf("parachainHeader: %#x", parachainHeader)
		}
	}
}

// TODO: fix build mmr proof from header
func TestBuildAndVerifyParaHeaderProofLocal1(t *testing.T) {
	t.Skip("fix build mmr proof from header")
	relayApi, err := gsrpc.NewSubstrateAPI(beefy.LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)

	latestFinalizedHash, err := relayApi.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	// t.Logf("latestFinalizedHash: %#x", latestFinalizedHash)
	latestFinalizedHeader, err := relayApi.RPC.Chain.GetHeader(latestFinalizedHash)
	// endFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(endBlockNumber))
	require.NoError(t, err)
	t.Logf("latestFinalizedHeader: %+v", latestFinalizedHeader)

	toBlockNumber := latestFinalizedHeader.Number

	fromBlockNumber := toBlockNumber - 7
	t.Logf("fromBlockNumber: %d toBlockNumber: %d", fromBlockNumber, toBlockNumber)

	fromFinalizedHash, err := relayApi.RPC.Chain.GetBlockHash(uint64(fromBlockNumber))
	require.NoError(t, err)
	t.Logf("fromBlockHash: %#x ", fromFinalizedHash)
	// t.Logf("toBlockNumber: %d", toBlockNumber)
	t.Logf("toBlockHash: %#x", latestFinalizedHash)

	changeSets, err := beefy.QueryParachainStorage(relayApi, beefy.LOCAL_PARACHAIN_ID, fromFinalizedHash, latestFinalizedHash)
	require.NoError(t, err)
	t.Logf("changeSet len: %d", len(changeSets))
	for _, changeSet := range changeSets {
		header, err := relayApi.RPC.Chain.GetHeader(changeSet.Block)
		require.NoError(t, err)
		// t.Logf("fromBlockHash: %#x ", fromFinalizedHash)
		t.Logf("changeSet blockHash: %d changeSet blockHash: %#x", header.Number, changeSet.Block)
		hexStr, err := json.Marshal(changeSet.Changes)
		require.NoError(t, err)
		t.Logf("changeSet changes: %s", hexStr)
		for _, change := range changeSet.Changes {

			t.Logf("change.StorageKey: %#x", change.StorageKey)
			t.Logf("change.HasStorageData: %#v", change.HasStorageData)
			t.Logf("change.HasStorageData: %#x", change.StorageData)
		}
	}

	// find all the relay chain header that includes target parachain header
	relayerHeaderMap, relayChainHeaderIdxes, err := beefy.BuildRelaychainHeaderMap(relayApi, latestFinalizedHash, changeSets)
	require.NoError(t, err)
	t.Logf("relayerHeaderMap len: %d", len(relayerHeaderMap))
	t.Logf("relayChainHeaderIdxes: %+v", relayChainHeaderIdxes)
	// t.Logf("relayerHeaderMap: %+v", relayerHeaderMap)
	for number, parachainMap := range relayerHeaderMap {
		t.Logf("relayerHeaderMap at block: %d includes parachain header count: %d", number, len(parachainMap))
		// t.Logf("parachainHeader len: %d", )
		for pardId, parachainHeader := range parachainMap {
			t.Logf("parachain id: %d", pardId)
			t.Logf("parachainHeader: %#x", parachainHeader)
		}
	}

	// build mmr batch proofs for leaves containing target parachain header
	mmrBatchProof, err := beefy.BuildMMRBatchProof(relayApi, &latestFinalizedHash, relayChainHeaderIdxes)
	require.NoError(t, err)
	// t.Logf("mmrBatchProof: %+v", mmrBatchProof)
	t.Logf("mmrBatchProof.BlockHash: %#x", mmrBatchProof.BlockHash)
	t.Logf("mmrBatchProof leaves len: %d", len(mmrBatchProof.Leaves))
	t.Logf("mmrBatchProof.Proof.LeafCount: %d", mmrBatchProof.Proof.LeafCount)
	for _, leaf := range mmrBatchProof.Leaves {
		t.Logf("mmrBatchProof leaf: %+v", leaf)
	}
	t.Logf("mmrBatchProof leaf indexes: %+v", mmrBatchProof.Proof.LeafIndexes)
	t.Logf("mmrBatchProof leaf count: %d", mmrBatchProof.Proof.LeafCount)

	// var mmrBatchProofItems = make([][]byte, len(mmrBatchProof.Proof.Items))
	// for i := 0; i < len(mmrBatchProof.Proof.Items); i++ {
	// 	mmrBatchProofItems[i] = mmrBatchProof.Proof.Items[i][:]
	// }
	// t.Logf("mmrBatchProof Proof Items count: %d", len(mmrBatchProofItems))
	// for _, item := range mmrBatchProofItems {
	// 	t.Logf("mmrBatchProof Proof Item: %#x", item)
	// }

	// build para chain head proof
	targetParaHeaderWithProofs, err := beefy.BuildParachainHeaderProof(relayApi, latestFinalizedHash, mmrBatchProof,
		relayerHeaderMap, beefy.LOCAL_PARACHAIN_ID)
	require.NoError(t, err)
	t.Logf("targetParaHeaderWithProofs: %+v", targetParaHeaderWithProofs)

	// // build mmr proof from para headers proof
	leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(beefy.BEEFY_ACTIVATION_BLOCK, uint32(toBlockNumber))
	// t.Logf("leafIndex: %d", leafIndex)
	mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
	// mmrSize := mmr.LeafIndexToMMRSize(uint64(mmrBatchProof.Proof.LeafCount))
	t.Logf("leafIndex: %d mmrSize: %d", leafIndex, mmrSize)
	mmrProof, err := beefy.BuildMMRProofFromParaHeaders(targetParaHeaderWithProofs, mmrSize, mmrBatchProof)
	require.NoError(t, err)
	t.Logf("build mmrProof: %+v", mmrProof)
	mmrRoot, err := mmrProof.CalculateRoot()
	require.NoError(t, err)
	t.Logf("build mmr root: %#x", mmrRoot)
	// beefy.VerifyParaChainHeaderProofs()
}

//TODO: fix build mmr proof from header
func TestBuildAndVerifyParaHeaderProofLocal2(t *testing.T) {
	t.Skip("fix build mmr proof from header")
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

			}

			relayerHeaderMap, relayChainHeaderIdxes, err := beefy.BuildRelaychainHeaderMap(api, latestSignedCommitmentBlockHash, changeSets)
			require.NoError(t, err)
			t.Logf("relayerHeaderMap len: %d", len(relayerHeaderMap))
			t.Logf("relayChainHeaderIdxes: %+v", relayChainHeaderIdxes)
			// t.Logf("relayerHeaderMap: %+v", relayerHeaderMap)
			for number, parachainMap := range relayerHeaderMap {
				t.Logf("relayerHeaderMap at block: %d includes parachain header count: %d", number, len(parachainMap))
				// t.Logf("parachainHeader len: %d", )
				for pardId, parachainHeader := range parachainMap {
					t.Logf("parachain id: %d", pardId)
					t.Logf("parachainHeader: %#x", parachainHeader)
				}
			}

			// build mmr proofs for leaves containing target paraId
			mmrBatchProof, err := beefy.BuildMMRBatchProof(api, &latestSignedCommitmentBlockHash, relayChainHeaderIdxes)
			require.NoError(t, err)
			// t.Logf("mmrBatchProof: %+v", mmrBatchProof)
			t.Logf("mmrBatchProof.BlockHash: %#x", mmrBatchProof.BlockHash)
			t.Logf("mmrBatchProof leaves count: %d", len(mmrBatchProof.Leaves))
			for _, leaf := range mmrBatchProof.Leaves {
				t.Logf("mmrBatchProof leaf: %+v", leaf)
			}
			t.Logf("relayChainHeaderIdxes: %+v", relayChainHeaderIdxes)
			t.Logf("mmrBatchProof leaf indexes: %+v", mmrBatchProof.Proof.LeafIndexes)
			t.Logf("mmrBatchProof leaf count: %d", mmrBatchProof.Proof.LeafCount)

			// var mmrBatchProofItems = make([][]byte, len(mmrBatchProof.Proof.Items))
			// for i := 0; i < len(mmrBatchProof.Proof.Items); i++ {
			// 	mmrBatchProofItems[i] = mmrBatchProof.Proof.Items[i][:]
			// }
			// t.Logf("mmrBatchProof Proof Items count: %d", len(mmrBatchProofItems))
			// for _, item := range mmrBatchProofItems {
			// 	t.Logf("mmrBatchProof Proof Item: %#x", item)
			// }

			//----------------
			// build para chain head proof
			targetParaHeaderWithProofs, err := beefy.BuildParachainHeaderProof(api, latestSignedCommitmentBlockHash,
				mmrBatchProof, relayerHeaderMap, beefy.LOCAL_PARACHAIN_ID)
			require.NoError(t, err)
			t.Logf("targetParaHeaderWithProofs: %+v", targetParaHeaderWithProofs)

			// // build mmr proof from para headers proof
			// t.Logf("leafIndex: %d", leafIndex)
			// I think the mmr size can get from MmrBatchProof.LeafCount,don`not calculate
			// MmrProof is a MMR proof
			// type MmrBatchProof struct {
			// 	// The index of the leaf the proof is for.
			// 	LeafIndex []types.U64
			// 	// Number of leaves in MMR, when the proof was generated.
			// 	LeafCount types.U64
			// 	// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
			// 	Items []types.H256
			// }
			leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(beefy.BEEFY_ACTIVATION_BLOCK, uint32(latestSignedCommitmentBlockNumber))
			// leafIndex := latestSignedCommitmentBlockNumber
			mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
			// mmrSize := mmr.LeafIndexToMMRSize(uint64(mmrBatchProof.Proof.LeafCount))
			t.Logf("leafIndex: %d mmrSize: %d", leafIndex, mmrSize)
			mmrProof, err := beefy.BuildMMRProofFromParaHeaders(targetParaHeaderWithProofs, mmrSize, mmrBatchProof)
			require.NoError(t, err)
			t.Logf("build mmrProof: %+v", mmrProof)
			mmrRoot, err := mmrProof.CalculateRoot()
			require.NoError(t, err)
			t.Logf("build mmr root: %#x", mmrRoot)
			latestPayload := s.SignedCommitment.Commitment.Payload[0].Data
			t.Logf("latestPayload: %#x", latestPayload)
			// beefy.VerifyParaChainHeaderProofs()

			// save latestSignedCommitment for next verify
			preBlockNumber = latestSignedCommitmentBlockNumber
			preBloackHash = latestSignedCommitmentBlockHash
			//----------------
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

func TestBuildAndVerifyParaHeaderProofLocal3(t *testing.T) {
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
			t.Logf("The indexes of the leaf the proof is for: %+v", mmrBatchProof.Proof.LeafIndexes)
			t.Logf("Number of leaves in MMR, when the proof was generated: %d", mmrBatchProof.Proof.LeafCount)

			// verify mmr batch proof
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
					Index: uint64(mmrBatchProof.Proof.LeafIndexes[i]),
				}
				mmrLeaves[i] = mmrLeaf
			}
			mmrProof := mmr.NewProof(mmrSize, mmrLeafProof, mmrLeaves, hasher.Keccak256Hasher{})
			calMMRRoot, err := mmrProof.CalculateRoot()
			require.NoError(t, err)
			t.Log("------------------------------------------------------------------------------------")
			t.Logf("cal mmr root:%#x", calMMRRoot)
			t.Logf("payload.Data:%#x", s.SignedCommitment.Commitment.Payload[0].Data)
			t.Log("------------------------------------------------------------------------------------")

			// build parachain header proof and verify that proof
			leafLen := len(mmrBatchProof.Leaves)
			for i := 0; i < leafLen; i++ {
				targetLeafIndex := uint64(mmrBatchProof.Proof.LeafIndexes[i])
				targetLeafBlockHash, err := api.RPC.Chain.GetBlockHash(targetLeafIndex)
				require.NoError(t, err)
				t.Logf("targetLeafIndex: %d targetLeafBlockHash: %#x", leafIndex, targetLeafBlockHash)
				paraChainIds, err := beefy.GetParachainIds(api, targetLeafBlockHash)
				require.NoError(t, err)
				t.Logf("paraChainIds: %+v", paraChainIds)
				var paraChainHeaderMap = make(map[uint32][]byte, len(paraChainIds))
				//find relayer header that includes all the target parachain header
				for _, paraChainId := range paraChainIds {
					paraChainHeader, err := beefy.GetParachainHeader(api, uint32(paraChainId), targetLeafBlockHash)
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

				// verify new merkle root == mmrLeafParachainHeads
				mmrLeafParachainHeads := mmrBatchProof.Leaves[i].ParachainHeads
				t.Log("------------------------------------------------------------------------------------")
				t.Logf("cal merkle root from all parachain header proof: %#x", tree.Root())
				t.Logf("mmrBatchProof.Leaves[i].ParachainHeads: %#x", mmrLeafParachainHeads)
				t.Log("------------------------------------------------------------------------------------")

				// build merkle tree from target parachain proof
				targetParachainHeader := paraChainHeaderMap[targetParaId]
				encodedTargetParaHeader, err := codec.Encode(beefy.ParaIdAndHeader{ParaId: targetParaId, Header: targetParachainHeader})
				require.NoError(t, err)

				targetParaHeaderLeaves := []merkletypes.Leaf{
					{
						Hash:  crypto.Keccak256(encodedTargetParaHeader),
						Index: uint64(targetParaHeaderindex),
					},
				}
				paraHeadsProof := tree.Proof([]uint64{uint64(targetParaHeaderindex)})
				targetParachainHeaderProof := paraHeadsProof.ProofHashes()
				paraHeadsTotalCount := uint64(len(paraHeaderLeaves))
				parachainHeadsProof := merkle.NewProof(targetParaHeaderLeaves, targetParachainHeaderProof, paraHeadsTotalCount, hasher.Keccak256Hasher{})
				// todo: merkle.Proof.Root() should return fixed bytes
				// get merkle root
				parachainHeadsRoot, err := parachainHeadsProof.Root()
				require.NoError(t, err)
				// verify new merkle root == mmrLeafParachainHeads
				t.Log("------------------------------------------------------------------------------------")
				t.Logf("cal merkle root from target parachain header proof: %#x", parachainHeadsRoot)
				t.Logf("mmrBatchProof.Leaves[i].ParachainHeads: %#x", mmrLeafParachainHeads)
				t.Log("------------------------------------------------------------------------------------")

				// verify solochain header,the leaf parent hash == blake2b256(scale.encode(solochain header))
				targetLeafHeader, err := api.RPC.Chain.GetHeader(targetLeafBlockHash)
				require.NoError(t, err)
				t.Logf("targetLeafHeader: %+v", targetLeafHeader)
				ecodedLeafHeader, err := codec.Encode(targetLeafHeader)
				require.NoError(t, err)
				// targetRelayHeaderRehash, err := hasher.Keccak256Hasher{}.Hash(encodeTargetRelayerHeader)
				blake2b256, err := hash.NewBlake2b256(nil)
				require.NoError(t, err)
				_, err = blake2b256.Write(ecodedLeafHeader)
				leafHeaderRehash := blake2b256.Sum(nil)
				require.NoError(t, err)
				t.Logf("targetLeafHeaderRehash: %#x", leafHeaderRehash)
				t.Logf("\nleafIndex: %d mmrLeaf ParentNumber: %d \n leafHeader: %+v", leafIndex, mmrBatchProof.Leaves[i].ParentNumberAndHash.ParentNumber, targetLeafHeader)
				t.Logf("\nleafBlockHash: %#x\n mmrLeaf parent Hash: %#x\n targetLeafHeaderRehash: %#x", targetLeafBlockHash, mmrBatchProof.Leaves[i].ParentNumberAndHash.Hash, leafHeaderRehash)
				// TODO: save the targetParaHeader for  veify state proof
			}

			// verify parachain header proof use the beefy mmrLeaf.ParachainHeads

			// save latestSignedCommitment for next verify
			preBlockNumber = latestSignedCommitmentBlockNumber
			preBloackHash = latestSignedCommitmentBlockHash

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

func TestBuildAndVerifyParaHeaderProofLocal4(t *testing.T) {
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
			t.Logf("The indexes of the leaf the proof is for: %+v", mmrBatchProof.Proof.LeafIndexes)
			t.Logf("Number of leaves in MMR, when the proof was generated: %d", mmrBatchProof.Proof.LeafCount)

			// verify mmr batch proof
			// leafCount := mmrBatchProof.Proof.LeafCount
			// mmrSize := mmr.LeafIndexToMMRSize(uint64(leafCount))
			leafIndex := beefy.ConvertBlockNumberToMmrLeafIndex(uint32(beefy.BEEFY_ACTIVATION_BLOCK), latestSignedCommitmentBlockNumber)
			mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
			t.Logf("beefy.GetLeafIndexForBlockNumber(uint32(beefy.BEEFY_ACTIVATION_BLOCK), latestSignedCommitmentBlockNumber): %d", leafIndex)
			t.Logf("mmr.LeafIndexToMMRSize(uint64(leafIndex)): %d", mmrSize)

			//verify mmr batch proof
			t.Log("---  begin to verify mmr batch proof  ---")
			result, err := beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload,
				mmrSize, mmrBatchProof.Leaves, mmrBatchProof.Proof)
			require.NoError(t, err)
			t.Logf("beefy.VerifyMMRBatchProof(s.SignedCommitment.Commitment.Payload[0], mmrSize,mmrBatchProof.Leaves, mmrBatchProof.Proof) result: %+v", result)
			require.True(t, result)
			t.Log("---  end to verify mmr batch proof  ---\n")

			leafLen := len(mmrBatchProof.Leaves)
			t.Logf("leaf num: %d", leafLen)
			//verify relaychain header/solochain header

			t.Log("---  begin to verify solochain header  ---")
			// build solochain header map
			solochainHeaderMap, err := beefy.BuildSolochainHeaderMap(api, mmrBatchProof.Proof.LeafIndexes)
			require.NoError(t, err)
			t.Logf("solochainHeaderMap: %+v", solochainHeaderMap)

			// verify solochain and proof
			err = beefy.VerifySolochainHeader(mmrBatchProof.Leaves, solochainHeaderMap)
			require.NoError(t, err)
			t.Log("beefy.VerifySolochainHeader(mmrBatchProof.Leaves,solochainHeaderMap) result: True")
			// require.True(t, ret)
			t.Log("---  end to verify solochain header   ---\n")

			t.Log("---  begin to verify parachain header  ---")

			// build parachain header proof and verify that proof
			parachainHeaderMap, err := beefy.BuildParachainHeaderMap(api, mmrBatchProof.Proof.LeafIndexes, beefy.LOCAL_PARACHAIN_ID)
			require.NoError(t, err)
			t.Logf("parachainHeaderMap: %+v", parachainHeaderMap)
			err = beefy.VerifyParachainHeader(mmrBatchProof.Leaves, parachainHeaderMap)
			require.NoError(t, err)
			t.Log("beefy.VerifyParachainHeader(mmrBatchProof.Leaves, parachainHeaderMap) result: True")
			// require.True(t, ret)
			t.Log("---  end to verify parachain header  ---")

			// save latestSignedCommitment for next verify
			preBlockNumber = latestSignedCommitmentBlockNumber
			preBloackHash = latestSignedCommitmentBlockHash

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
