package beefy

import (
	"fmt"
	"log"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

type Timestamp struct {
	// the actual block timestamp
	Value uint64 `protobuf:"varint,1,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	// these proof gets from parachain by rpc methord:state_getReadProof
	Proofs [][]byte `protobuf:"bytes,2,rep,name=proofs,proto3" json:"proofs,omitempty"`
}

func BuildTimestampProof(conn *gsrpc.SubstrateAPI, blockHash types.Hash) (StateProof, error) {
	//  get timestamp and proof
	timestampValue, err := GetTimestampValue(conn, blockHash)
	if err != nil {
		return StateProof{}, err
	}
	proof, err := GetTimestampProof(conn, blockHash)
	if err != nil {
		return StateProof{}, err
	}
	// proofLen := len(timestampProof.Proof)
	// proofs := make([][]byte, proofLen)
	// for i := 0; i < proofLen; i++ {
	// 	copy(proofs[i], timestampProof.Proof[i][:])
	// }
	proofs := make([][]byte, len(proof.Proof))
	for i, v := range proof.Proof {
		// proofs = append(proofs, proof[:])
		proofs[i] = v[:]
	}
	log.Printf("timestampProof proofs: %#x", proofs)
	timestampKey := CreateStorageKeyPrefix("Timestamp", "Now")
	log.Printf("CreateStorageKeyPrefix(Timestamp, Now): %#x", timestampKey)

	timestamProof := StateProof{
		Key:    timestampKey,
		Value:  timestampValue[:],
		Proofs: proofs,
	}

	return timestamProof, nil

}

func GetTimestampValue(conn *gsrpc.SubstrateAPI, blockHash types.Hash) (types.Bytes, error) {
	// Fetch metadata
	meta, err := conn.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}

	storageKey, err := types.CreateStorageKey(meta, "Timestamp", "Now")
	if err != nil {
		return nil, err
	}
	log.Printf("storageKey: %#x", storageKey)

	var timestamp types.U64
	// var timestamp types.Bytes
	ok, err := conn.RPC.State.GetStorage(storageKey, &timestamp, blockHash)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("parachain header not found")
	}

	//TODO: must be encode
	// use grpc.codec.Encode() or trie_scale.Marshal() ?
	timestampBytes, err := codec.Encode(timestamp)
	if err != nil {
		return nil, err
	}

	return timestampBytes, nil
}
