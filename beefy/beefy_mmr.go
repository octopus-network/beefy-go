package beefy

import (
	"bytes"
	"encoding/json"
	"log"
	"reflect"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/client"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/mmr"
	merkletypes "github.com/ComposableFi/go-merkle-trees/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
)

type MMRLeafWithIndex struct {
	Index uint64
	Leaf  types.MMRLeaf
}

type MMRLeavesAndBatchProof struct {
	// mmr leaves
	Leaves []types.MMRLeaf `json:"leaves"`
	// mmr batch proof
	MmrBatchProof MMRBatchProof `protobuf:"bytes,2,opt,name=mmr_batch_proof,json=mmrBatchProof,proto3" json:"mmr_batch_proof"`
}

// MmrProof is a MMR proof
type MMRBatchProof struct {
	// The index of the leaf the proof is for.
	LeafIndex []types.U64
	// Number of leaves in MMR, when the proof was generated.
	LeafCount types.U64
	// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
	Items []types.H256
}

// GenerateMmrBatchProofResponse contains the generate batch proof rpc response
type GenerateMmrBatchProofResponse struct {
	BlockHash types.H256
	Leaves    []types.MMRLeaf
	Proof     MMRBatchProof
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

// GenerateProof retrieves a MMR proof and leaf for the specified leave index, at the given blockHash (useful to query a
// proof at an earlier block, likely with another MMR root)
func BuildMMRBatchProof(conn *gsrpc.SubstrateAPI, blockHash *types.Hash, idxes []uint64) (GenerateMmrBatchProofResponse, error) {
	var batchProofResp GenerateMmrBatchProofResponse
	err := client.CallWithBlockHash(conn.Client, &batchProofResp, "mmr_generateBatchProof", blockHash, idxes)
	if err != nil {
		return GenerateMmrBatchProofResponse{}, err
	}

	return batchProofResp, nil
}

// verify batch mmr proof
func VerifyMMRBatchProof(payloads []types.PayloadItem, mmrSize uint64, mmrLeaves []types.MMRLeaf, mmrbatchProof MMRBatchProof) (bool, error) {
	for _, payload := range payloads {
		mmrRootID := []byte("mh")
		log.Printf("\nmmrRootID: %s\npayload.ID: %s", mmrRootID, payload.ID)
		// checks for the right payloadId
		if bytes.Equal(payload.ID[:], mmrRootID) {
			leafNum := len(mmrLeaves)
			var leaves = make([]merkletypes.Leaf, leafNum)
			for i := 0; i < leafNum; i++ {
				// scale encode the mmr leaf
				encodedMMRLeaf, err := codec.Encode(mmrLeaves[i])
				if err != nil {
					return false, err
				}
				log.Printf("encodedMMRLeaf: %#x", encodedMMRLeaf)
				leaf := merkletypes.Leaf{
					Hash:  crypto.Keccak256(encodedMMRLeaf),
					Index: uint64(mmrbatchProof.LeafIndex[i]),
				}
				leaves[i] = leaf
			}

			var proofItmes = make([][]byte, len(mmrbatchProof.Items))
			for i := 0; i < len(mmrbatchProof.Items); i++ {
				proofItmes[i] = mmrbatchProof.Items[i][:]
			}

			mmrProof := mmr.NewProof(mmrSize, proofItmes, leaves, hasher.Keccak256Hasher{})
			calMMRRoot, err := mmrProof.CalculateRoot()

			if err != nil {
				return false, err
			}

			log.Printf("cal mmr root:%#x", calMMRRoot)
			log.Printf("payload.Data:%#x", payload.Data)
			ret := reflect.DeepEqual(calMMRRoot, payload.Data)
			log.Printf("reflect.DeepEqual result :%#v", ret)
			if !ret {
				return false, nil
			}

		}
	}

	return true, nil

}

// build single mmr proof
func BuildMMRProof(conn *gsrpc.SubstrateAPI, leafIndex uint64, blockHash types.Hash) (types.H256, types.MMRLeaf, types.MMRProof, error) {
	resp, err := conn.RPC.MMR.GenerateProof(leafIndex, blockHash)
	if err != nil {
		return types.H256{}, types.MMRLeaf{}, types.MMRProof{}, err
	}

	retBlockHash, mmrLeaf, mmrProof := resp.BlockHash, resp.Leaf, resp.Proof
	log.Printf("\nretBlockHash: %#x \nLeafIndex: %d \nmmrLeaf: %+v \nmrProof: %+v", retBlockHash, leafIndex, mmrLeaf, mmrProof)
	// var mmrLeafProof = make([][]byte, len(mmrProof.Items))
	// for i := 0; i < len(mmrProof.Items); i++ {
	// 	mmrLeafProof[i] = mmrProof.Items[i][:]
	// }

	return retBlockHash, mmrLeaf, mmrProof, nil

}

// verify single mmr proof
func VerifyMMRProof(commitment types.Commitment, mmrSize uint64, leafIndex uint64, mmrLeaf types.MMRLeaf, mmrLeafProof [][]byte) (bool, error) {
	for _, payload := range commitment.Payload {
		mmrRootID := []byte("mh")
		log.Printf("\nmmrRootID: %s\npayload.ID: %s", mmrRootID, payload.ID)
		// checks for the right payloadId
		if bytes.Equal(payload.ID[:], mmrRootID) {
			// the next authorities are in the latest BeefyMmrLeaf

			// scale encode the mmr leaf
			encodedMMRLeaf, err := codec.Encode(mmrLeaf)
			if err != nil {
				return false, err
			}
			log.Printf("encodedMMRLeaf: %#x", encodedMMRLeaf)

			// we treat this leaf as the latest leaf in the mmr
			// mmrSize := mmr.LeafIndexToMMRSize(leafIndex)
			// log.Printf("mmrSize:%d\n ", mmrSize)

			mmrLeaves := []merkletypes.Leaf{
				{
					Hash:  crypto.Keccak256(encodedMMRLeaf),
					Index: leafIndex,
				},
			}
			mmrProof := mmr.NewProof(mmrSize, mmrLeafProof, mmrLeaves, hasher.Keccak256Hasher{})

			// if !mmrProof.Verify(payload.Data) {
			// 	return false, err
			// }

			// break
			// verify that the leaf is valid, for the signed mmr-root-hash
			calMMRRoot, err := mmrProof.CalculateRoot()
			if err != nil {
				return false, err
			}
			log.Printf("cal mmr root:%#x\n ", calMMRRoot)
			log.Printf("payload.Data:%#x\n ", payload.Data)
			ret := reflect.DeepEqual(calMMRRoot, payload.Data)
			log.Printf("reflect.DeepEqual result :%#v", ret)

			break
		}
	}

	return true, nil

}
