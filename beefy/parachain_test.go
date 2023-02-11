package beefy_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ComposableFi/go-merkle-trees/mmr"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
	"github.com/octopus-network/beefy-go/beefy"
	"github.com/stretchr/testify/require"
)

func TestGetParaChainInfoLocal(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
	require.NoError(t, err)
	blockHash, err := api.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	paraChainIds, err := beefy.GetParaChainIDs(api, blockHash)
	require.NoError(t, err)
	t.Logf("paraChainIds: %+v", paraChainIds)
	for _, paraChainId := range paraChainIds {
		t.Logf("paraChainId: %d", paraChainId)
		paraChainHeader, err := beefy.GetParaChainHeader(api, uint32(paraChainId), blockHash)
		require.NoError(t, err)
		t.Logf("paraChainHeader: %#x", paraChainHeader)
	}
}

func TestGetParaChainInfoRococo(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(ROCOCO_ENDPOIN)
	require.NoError(t, err)
	blockHash, err := api.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	paraChainIds, err := beefy.GetParaChainIDs(api, blockHash)
	require.NoError(t, err)
	t.Logf("paraChainIds: %+v", paraChainIds)
	for _, paraChainId := range paraChainIds {
		t.Logf("paraChainId: %d", paraChainId)
		paraChainHeader, err := beefy.GetParaChainHeader(api, uint32(paraChainId), blockHash)
		require.NoError(t, err)
		t.Logf("paraChainHeader: %#x", paraChainHeader)
		var decodeParachainHeader types.Header
		err = codec.Decode(paraChainHeader, &decodeParachainHeader)
		require.NoError(t, err)
		t.Logf("decodeParachainHeader: %+v", decodeParachainHeader)
	}
}

func TestGetParaChainInfoPolkadot(t *testing.T) {
	api, err := gsrpc.NewSubstrateAPI(POLKADOT_ENDPOINT)
	require.NoError(t, err)
	blockHash, err := api.RPC.Chain.GetFinalizedHead()
	require.NoError(t, err)
	t.Logf("blockHash: %#x", blockHash)
	paraChainIds, err := beefy.GetParaChainIDs(api, blockHash)
	require.NoError(t, err)
	t.Logf("paraChainIds: %+v", paraChainIds)
	for _, paraChainId := range paraChainIds {
		t.Logf("paraChainId: %d", paraChainId)
		paraChainHeader, err := beefy.GetParaChainHeader(api, uint32(paraChainId), blockHash)
		require.NoError(t, err)
		t.Logf("paraChainHeader: %#x", paraChainHeader)
		var decodeParachainHeader types.Header
		err = codec.Decode(paraChainHeader, &decodeParachainHeader)
		require.NoError(t, err)
		t.Logf("decodeParachainHeader: %+v", decodeParachainHeader)
	}

}

func TestQueryParaChainStorageLocal(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
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

	changeSets, err := beefy.QueryParaChainStorage(relayApi, LOCAL_PARACHAIN_ID, fromFinalizedHash, latestFinalizedHash)
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

func TestBuildRelayerHeaderMapLocal(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
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

	changeSets, err := beefy.QueryParaChainStorage(relayApi, LOCAL_PARACHAIN_ID, fromFinalizedHash, latestFinalizedHash)
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

	relayerHeaderMap, relayChainHeaderIdxes, err := beefy.BuildRelayerHeaderMap(relayApi, latestFinalizedHash, changeSets)
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

func TestBuildAndVerifyParaHeaderProofLocal(t *testing.T) {

	relayApi, err := gsrpc.NewSubstrateAPI(LOCAL_RELAY_ENDPPOIT)
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

	changeSets, err := beefy.QueryParaChainStorage(relayApi, LOCAL_PARACHAIN_ID, fromFinalizedHash, latestFinalizedHash)
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

	relayerHeaderMap, relayChainHeaderIdxes, err := beefy.BuildRelayerHeaderMap(relayApi, latestFinalizedHash, changeSets)
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
	mmrBatchProof, err := beefy.BuildMMRBatchProof(relayApi, &latestFinalizedHash, relayChainHeaderIdxes)
	require.NoError(t, err)
	// t.Logf("mmrBatchProof: %+v", mmrBatchProof)
	t.Logf("mmrBatchProof.BlockHash: %#x", mmrBatchProof.BlockHash)
	t.Logf("mmrBatchProof leaves count: %d", len(mmrBatchProof.Leaves))
	for _, leaf := range mmrBatchProof.Leaves {
		t.Logf("mmrBatchProof leaf: %+v", leaf)
	}
	t.Logf("mmrBatchProof leaf indexes: %+v", mmrBatchProof.Proof.LeafIndex)
	t.Logf("mmrBatchProof leaf count: %d", mmrBatchProof.Proof.LeafCount)

	var mmrBatchProofItems = make([][]byte, len(mmrBatchProof.Proof.Items))
	for i := 0; i < len(mmrBatchProof.Proof.Items); i++ {
		mmrBatchProofItems[i] = mmrBatchProof.Proof.Items[i][:]
	}
	t.Logf("mmrBatchProof Proof Items count: %d", len(mmrBatchProofItems))
	for _, item := range mmrBatchProofItems {
		t.Logf("mmrBatchProof Proof Item: %#x", item)
	}

	// build para chain head proof
	targetParaHeaderWithProofs, err := beefy.BuildTargetParaHeaderProof(relayApi, latestFinalizedHash, mmrBatchProof, relayerHeaderMap, LOCAL_PARACHAIN_ID)
	require.NoError(t, err)
	t.Logf("targetParaHeaderWithProofs: %+v", targetParaHeaderWithProofs)

	// // build mmr proof from para headers proof
	leafIndex := beefy.GetLeafIndexForBlockNumber(beefy.BEEFY_ACTIVATION_BLOCK, uint32(toBlockNumber))
	// t.Logf("leafIndex: %d", leafIndex)
	mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
	t.Logf("leafIndex: %d mmrSize: %d", leafIndex, mmrSize)
	mmrProof, err := beefy.BuildMMRProofFromParaHeaders(targetParaHeaderWithProofs, mmrSize, mmrBatchProofItems)
	require.NoError(t, err)
	t.Logf("build mmrProof: %+v", mmrProof)
	mmrRoot, err := mmrProof.CalculateRoot()
	require.NoError(t, err)
	t.Logf("build mmr root: %#x", mmrRoot)
	// beefy.VerifyParaChainHeaderProofs()
}

func TestBuildAndVerifyParaHeaderProofLocal2(t *testing.T) {
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

	require.NoError(t, err)

	t.Logf("subscribed to %s\n", LOCAL_RELAY_ENDPPOIT)

	defer sub.Unsubscribe()

	timeout := time.After(24 * time.Hour)
	received := 0

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
			latestBlockNumber := s.SignedCommitment.Commitment.BlockNumber
			t.Logf("blockNumber: %d\n", latestBlockNumber)
			latestFinalizedHash, err := api.RPC.Chain.GetBlockHash(uint64(latestBlockNumber))
			require.NoError(t, err)
			t.Logf("blockHash: %#x", latestFinalizedHash)

			fromBlockNumber := latestBlockNumber - 7
			t.Logf("fromBlockNumber: %d toBlockNumber: %d", fromBlockNumber, latestBlockNumber)

			fromFinalizedHash, err := api.RPC.Chain.GetBlockHash(uint64(fromBlockNumber))
			require.NoError(t, err)
			t.Logf("fromBlockHash: %#x ", fromFinalizedHash)
			// t.Logf("toBlockNumber: %d", toBlockNumber)
			t.Logf("toBlockHash: %#x", latestFinalizedHash)

			changeSets, err := beefy.QueryParaChainStorage(api, LOCAL_PARACHAIN_ID, fromFinalizedHash, latestFinalizedHash)
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

			relayerHeaderMap, relayChainHeaderIdxes, err := beefy.BuildRelayerHeaderMap(api, latestFinalizedHash, changeSets)
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
			mmrBatchProof, err := beefy.BuildMMRBatchProof(api, &latestFinalizedHash, relayChainHeaderIdxes)
			require.NoError(t, err)
			// t.Logf("mmrBatchProof: %+v", mmrBatchProof)
			t.Logf("mmrBatchProof.BlockHash: %#x", mmrBatchProof.BlockHash)
			t.Logf("mmrBatchProof leaves count: %d", len(mmrBatchProof.Leaves))
			for _, leaf := range mmrBatchProof.Leaves {
				t.Logf("mmrBatchProof leaf: %+v", leaf)
			}
			t.Logf("mmrBatchProof leaf indexes: %+v", mmrBatchProof.Proof.LeafIndex)
			t.Logf("mmrBatchProof leaf count: %d", mmrBatchProof.Proof.LeafCount)

			var mmrBatchProofItems = make([][]byte, len(mmrBatchProof.Proof.Items))
			for i := 0; i < len(mmrBatchProof.Proof.Items); i++ {
				mmrBatchProofItems[i] = mmrBatchProof.Proof.Items[i][:]
			}
			t.Logf("mmrBatchProof Proof Items count: %d", len(mmrBatchProofItems))
			for _, item := range mmrBatchProofItems {
				t.Logf("mmrBatchProof Proof Item: %#x", item)
			}

			// build para chain head proof
			targetParaHeaderWithProofs, err := beefy.BuildTargetParaHeaderProof(api, latestFinalizedHash, mmrBatchProof, relayerHeaderMap, LOCAL_PARACHAIN_ID)
			require.NoError(t, err)
			t.Logf("targetParaHeaderWithProofs: %+v", targetParaHeaderWithProofs)

			// // build mmr proof from para headers proof
			leafIndex := beefy.GetLeafIndexForBlockNumber(beefy.BEEFY_ACTIVATION_BLOCK, uint32(latestBlockNumber))
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
			mmrSize := mmr.LeafIndexToMMRSize(uint64(leafIndex))
			t.Logf("leafIndex: %d mmrSize: %d", leafIndex, mmrSize)
			mmrProof, err := beefy.BuildMMRProofFromParaHeaders(targetParaHeaderWithProofs, mmrSize, mmrBatchProofItems)
			require.NoError(t, err)
			t.Logf("build mmrProof: %+v", mmrProof)
			mmrRoot, err := mmrProof.CalculateRoot()
			require.NoError(t, err)
			t.Logf("build mmr root: %#x", mmrRoot)
			latestPayload := s.SignedCommitment.Commitment.Payload[0].Data
			t.Logf("latestPayload: %#x", latestPayload)
			// beefy.VerifyParaChainHeaderProofs()

			received++

			if received >= 100 {
				return
			}
		case <-timeout:
			t.Logf("timeout reached without getting 2 notifications from subscription")
			return
		}
	}
}

func TestQueryStorageRococo(t *testing.T) {
	relayApi, err := gsrpc.NewSubstrateAPI(ROCOCO_ENDPOIN)
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
	t.Logf("ROCOCO_PARACHAIN_ID: %d", ROCOCO_ROCKMIN_ID)
	encodedParaID, err := codec.Encode(ROCOCO_ROCKMIN_ID)
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
