package beefy

import (
	"encoding/json"

	"github.com/centrifuge/go-substrate-rpc-client/client"
	"github.com/centrifuge/go-substrate-rpc-client/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"

	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

// MmrProof is a MMR proof
type MmrBatchProof struct {
	// The index of the leaf the proof is for.
	LeafIndex []types.U64
	// Number of leaves in MMR, when the proof was generated.
	LeafCount types.U64
	// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
	Items []types.H256
}

// GenerateProof retrieves a MMR proof and leaf for the specified leave index, at the given blockHash (useful to query a
// proof at an earlier block, likely with another MMR root)
func GenerateMmrBatchProof(conn *gsrpc.SubstrateAPI, blockHash *types.Hash, indices []uint64) (GenerateMmrBatchProofResponse, error) {
	var res GenerateMmrBatchProofResponse
	err := client.CallWithBlockHash(conn.Client, &res, "mmr_generateBatchProof", blockHash, indices)
	if err != nil {
		return GenerateMmrBatchProofResponse{}, err
	}

	return res, nil
}

// GenerateMmrBatchProofResponse contains the generate batch proof rpc response
type GenerateMmrBatchProofResponse struct {
	BlockHash types.H256
	Leaves    []types.MMRLeaf
	Proof     MmrBatchProof
}

// UnmarshalJSON fills u with the JSON encoded byte array given by b
func (d *GenerateMmrBatchProofResponse) UnmarshalJSON(bz []byte) error {
	var tmp struct {
		BlockHash string `json:"blockHash"`
		Leaves    string `json:"leaves"`
		Proof     string `json:"proof"`
	}
	if err := json.Unmarshal(bz, &tmp); err != nil {
		return err
	}
	err := codec.DecodeFromHex(tmp.BlockHash, &d.BlockHash)
	if err != nil {
		return err
	}

	var opaqueLeaves [][]byte
	err = codec.DecodeFromHex(tmp.Leaves, &opaqueLeaves)
	if err != nil {
		return err
	}
	for _, leaf := range opaqueLeaves {

		var mmrLeaf types.MMRLeaf
		err := codec.Decode(leaf, &mmrLeaf)
		if err != nil {
			return err
		}
		d.Leaves = append(d.Leaves, mmrLeaf)
	}
	err = codec.DecodeFromHex(tmp.Proof, &d.Proof)
	if err != nil {
		return err
	}
	return nil
}
