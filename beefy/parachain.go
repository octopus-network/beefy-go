package beefy

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/OneOfOne/xxhash"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

type ParaIdAndHeader struct {
	ParaId uint32
	Header []byte
}

func FetchParachainHeader(conn *gsrpc.SubstrateAPI, paraId uint32, blockHash types.Hash) ([]byte, error) {
	// Fetch metadata
	meta, err := conn.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}

	paraIdEncoded := make([]byte, 4)
	binary.LittleEndian.PutUint32(paraIdEncoded, paraId)

	storageKey, err := types.CreateStorageKey(meta, "Paras", "Heads", paraIdEncoded)

	if err != nil {
		return nil, err
	}

	var parachainHeaders []byte

	ok, err := conn.RPC.State.GetStorage(storageKey, &parachainHeaders, blockHash)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("parachain header not found")
	}

	return parachainHeaders, nil
}

func FetchParaIDs(conn *gsrpc.SubstrateAPI, blockHash types.Hash) ([]uint32, error) {
	// Fetch metadata
	meta, err := conn.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}

	storageKey, err := types.CreateStorageKey(meta, "Paras", "Parachains", nil, nil)
	if err != nil {
		return nil, err
	}

	var paraIds []uint32

	ok, err := conn.RPC.State.GetStorage(storageKey, &paraIds, blockHash)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("beefy authorities not found")
	}

	return paraIds, nil
}

func QueryParaChainStorage(conn *gsrpc.SubstrateAPI, paraID uint32, startBlockNumber uint32, endBlockNumber uint32) ([]types.StorageChangeSet, error) {

	log.Printf("startBlockNumber: %d", startBlockNumber)
	log.Printf("endBlockNumber: %d", endBlockNumber)
	log.Printf("parachian id : %d", paraID)
	var paraHeaderKeys []types.StorageKey

	// create full storage key for our own paraId
	keyPrefix := CreateStorageKeyPrefix("Paras", "Heads")
	log.Printf("keyPrefix: %s", codec.HexEncodeToString(keyPrefix[:]))
	encodedParaID, err := codec.Encode(paraID)
	log.Printf("encodedParaID: %s", codec.HexEncodeToString(encodedParaID[:]))
	if err != nil {
		return []types.StorageChangeSet{}, err
	}

	twoXHash := xxhash.New64(encodedParaID).Sum(nil)
	log.Printf("encodedParaID twoXHash: %s", codec.HexEncodeToString(twoXHash[:]))
	// full key path in the storage source: https://www.shawntabrizi.com/assets/presentations/substrate-storage-deep-dive.pdf
	// xx128("Paras") + xx128("Heads") + xx64(Encode(paraId)) + Encode(paraId)
	fullKey := append(append(keyPrefix, twoXHash[:]...), encodedParaID...)
	log.Printf("fullKey: %s", codec.HexEncodeToString(fullKey[:]))
	paraHeaderKeys = append(paraHeaderKeys, fullKey)

	var changSet []types.StorageChangeSet

	for i := startBlockNumber; i <= endBlockNumber; i++ {
		blockHash, err := conn.RPC.Chain.GetBlockHash(uint64(i))
		if err != nil {
			return []types.StorageChangeSet{}, err
		}
		log.Printf("blockHash: %s\n", codec.HexEncodeToString(blockHash[:]))

		cs, err := conn.RPC.State.QueryStorageAt(paraHeaderKeys, blockHash)
		if err != nil {
			return []types.StorageChangeSet{}, err
		}
		log.Printf("cs: %#v", cs)

		changSet = append(changSet, cs...)
		// log.Printf("changeSet: %#v", changeSet)

	}
	log.Printf("changeSet: %#v", changSet)

	return changSet, nil
}
