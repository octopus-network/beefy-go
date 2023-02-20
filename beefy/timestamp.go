package beefy

import (
	"fmt"
	"log"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

type Timestamp struct {
	// the actual block timestamp
	Value uint64 `protobuf:"varint,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// these proof gets from parachain by rpc methord:state_getReadProof
	Proofs [][]byte `protobuf:"bytes,2,rep,name=proofs,proto3" json:"proofs,omitempty"`
}

func BuildTimestamp(conn *gsrpc.SubstrateAPI, blockHash types.Hash) (Timestamp, error) {
	//  get timestamp and proof
	timestampValue, err := GetTimestampValue(conn, blockHash)
	if err != nil {
		return Timestamp{}, err
	}
	timestampProof, err := GetTimestampProof(conn, blockHash)
	if err != nil {
		return Timestamp{}, err
	}
	// proofLen := len(timestampProof.Proof)
	// proofs := make([][]byte, proofLen)
	// for i := 0; i < proofLen; i++ {
	// 	copy(proofs[i], timestampProof.Proof[i][:])
	// }

	proofs := make([][]byte, len(timestampProof.Proof))
	for i, v := range timestampProof.Proof {
		// proofs = append(proofs, proof[:])
		proofs[i] = v[:]
	}
	log.Printf("timestampProof proofs: %#x", proofs)

	timestamp := Timestamp{
		Value:  uint64(timestampValue),
		Proofs: proofs,
	}

	return timestamp, nil

}

func GetTimestampValue(conn *gsrpc.SubstrateAPI, blockHash types.Hash) (types.U64, error) {
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
