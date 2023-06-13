package beefy

import (
	"encoding/binary"
	"encoding/json"
	"log"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/client"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
	tproof "github.com/octopus-network/trie-go/trie/proof"
)

// CreateStorageKeyPrefix creates a key prefix for keys of a map.
// Can be used as an input to the state.GetKeys() RPC, in order to list the keys of map.
func CreateStorageKeyPrefix(prefix, method string) []byte {
	return append(xxhash.New128([]byte(prefix)).Sum(nil), xxhash.New128([]byte(method)).Sum(nil)...)
}

type StateProof struct {
	// storage key
	Key []byte `json:"key,omitempty"`
	// the scale encode value
	Value []byte ` json:"timestamp,omitempty"`
	// these proof gets from parachain by rpc methord:state_getReadProof
	Proofs [][]byte `json:"proofs,omitempty"`
}

type ReadProofResponse struct {
	At    types.Hash
	Proof []types.Bytes
}

type ReadProof struct {
	At    string   `json:"at"`
	Proof []string `json:"proof"`
}

// UnmarshalJSON fills u with the JSON encoded byte array given by b
func (d *ReadProofResponse) UnmarshalJSON(bz []byte) error {
	var rp ReadProof
	if err := json.Unmarshal(bz, &rp); err != nil {
		return err
	}
	log.Printf("rp: %v", rp)

	err := codec.DecodeFromHex(rp.At, &d.At)
	if err != nil {
		return err
	}
	log.Printf("ReadProofResponse AT: %#x", d.At)

	for _, p := range rp.Proof {
		// var proof types.Bytes
		proof, err := codec.HexDecodeString(p)
		if err != nil {
			return err
		}
		d.Proof = append(d.Proof, proof)
	}
	// log.Printf("ReadProofResponse Proof: %+v", d.Proof)
	return nil
}

func GetStateProof(conn *gsrpc.SubstrateAPI, blockHash types.Hash, storageKeys []string) (ReadProofResponse, error) {
	var rp ReadProofResponse
	err := client.CallWithBlockHash(conn.Client, &rp, "state_getReadProof", &blockHash, storageKeys)
	if err != nil {
		return rp, err
	}
	// log.Printf("read proof: %+v", rp)
	return rp, nil
}

func GetParachainHeaderProof(conn *gsrpc.SubstrateAPI, blockHash types.Hash, paraId uint32) (ReadProofResponse, error) {

	var rp ReadProofResponse
	// Fetch metadata
	meta, err := conn.RPC.State.GetMetadataLatest()
	if err != nil {

		return rp, err
	}
	var storageKeys []types.StorageKey

	paraIdEncoded := make([]byte, 4)
	binary.LittleEndian.PutUint32(paraIdEncoded, paraId)
	storageKey, err := types.CreateStorageKey(meta, "Paras", "Heads", paraIdEncoded)
	if err != nil {
		return rp, err
	}
	log.Printf("storageKey: %#x", storageKey)
	storageKeys = append(storageKeys, storageKey)
	hexKeys := make([]string, len(storageKeys))
	for i, key := range storageKeys {
		hexKeys[i] = key.Hex()
	}
	log.Printf("hexKeys: %+v", hexKeys)

	rp, err = GetStateProof(conn, blockHash, hexKeys)
	if err != nil {
		return rp, err
	}
	return rp, nil

}

func GetTimestampProof(conn *gsrpc.SubstrateAPI, blockHash types.Hash) (ReadProofResponse, error) {

	var rp ReadProofResponse
	// Fetch metadata
	meta, err := conn.RPC.State.GetMetadataLatest()
	if err != nil {

		return rp, err
	}
	var storageKeys []types.StorageKey
	storageKey, err := types.CreateStorageKey(meta, "Timestamp", "Now")
	if err != nil {
		return rp, err
	}
	log.Printf("storageKey: %#x", storageKey)
	storageKeys = append(storageKeys, storageKey)
	hexKeys := make([]string, len(storageKeys))
	for i, key := range storageKeys {
		hexKeys[i] = key.Hex()
	}
	log.Printf("hexKeys: %+v", hexKeys)

	rp, err = GetStateProof(conn, blockHash, hexKeys)
	if err != nil {
		return rp, err
	}
	return rp, nil

}

// verify state proof
// Note: The value must be scale encoded
func VerifyStateProof(stateProof [][]byte, stateRoot []byte, key []byte, value []byte) error {

	err := tproof.Verify(stateProof, stateRoot, key, value)

	if err != nil {
		return err
	}
	return nil

}
