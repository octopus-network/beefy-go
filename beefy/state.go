package beefy

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/client"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

func GetParaChainTimestamp(conn *gsrpc.SubstrateAPI, blockHash types.Hash) (types.U64, error) {
	// Fetch metadata
	meta, err := conn.RPC.State.GetMetadataLatest()
	if err != nil {
		return 0, err
	}

	storageKey, err := types.CreateStorageKey(meta, "Timestamp", "Now")
	if err != nil {
		return 0, err
	}
	log.Printf("storageKey: %#x", storageKey)

	var timestamp types.U64

	ok, err := conn.RPC.State.GetStorage(storageKey, &timestamp, blockHash)
	if err != nil {
		return 0, err
	}

	if !ok {
		return 0, fmt.Errorf("parachain header not found")
	}

	return timestamp, nil
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
	// var rp struct {
	// 	At    string `json:"at"`
	// 	Proof string `json:"proof"`
	// }
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

	// d.Proof = make([]types.Bytes, len(rp.Proof))
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

func GetParaHeaderProof(conn *gsrpc.SubstrateAPI, blockHash types.Hash, paraId uint32) (ReadProofResponse, error) {

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

	// err = client.CallWithBlockHash(conn.Client, &rp, "state_getReadProof", &blockHash, hexKeys)
	// if err != nil {
	// 	return rp, err
	// }
	// // log.Printf("read proof: %+v", rp)

	rp, err = GetStateProof(conn, blockHash, hexKeys)
	if err != nil {
		return rp, err
	}
	return rp, nil

}

//TODO: verifyTimestamp Proof
func VerifyTimestampProof() {

}
