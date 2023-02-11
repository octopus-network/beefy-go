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

const BEEFY_ACTIVATION_BLOCK uint32 = 0

type LeafWithIndex struct {
	Leaf  types.MMRLeaf
	Index uint64
}

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
func BuildMMRBatchProof(conn *gsrpc.SubstrateAPI, blockHash *types.Hash, idxes []uint64) (GenerateMmrBatchProofResponse, error) {
	var batchProofResp GenerateMmrBatchProofResponse
	err := client.CallWithBlockHash(conn.Client, &batchProofResp, "mmr_generateBatchProof", blockHash, idxes)
	if err != nil {
		return GenerateMmrBatchProofResponse{}, err
	}

	return batchProofResp, nil
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
func GetBlockNumberForLeaf(beefyActivationBlock uint32, leafIndex uint32) uint32 {
	var blockNumber uint32

	// calculate the leafIndex for this leaf.
	if beefyActivationBlock == 0 {
		// in this case the leaf index is the same as the block number - 1 (leaf index starts at 0)
		blockNumber = leafIndex + 1
	} else {
		// in this case the leaf index is activation block - current block number.
		blockNumber = beefyActivationBlock + leafIndex
	}

	return blockNumber
}

// GetLeafIndexForBlockNumber given the MmrLeafPartial.ParentNumber & BeefyActivationBlock,
func GetLeafIndexForBlockNumber(beefyActivationBlock uint32, blockNumber uint32) uint64 {
	var leafIndex uint32

	// calculate the leafIndex for this leaf.
	if beefyActivationBlock == 0 {
		// in this case the leaf index is the same as the block number - 1 (leaf index starts at 0)
		leafIndex = blockNumber - 1
	} else {
		// in this case the leaf index is activation block - current block number.
		leafIndex = beefyActivationBlock - (blockNumber + 1)
	}

	return uint64(leafIndex)
}

func BuildMMRProof(conn *gsrpc.SubstrateAPI, leafIndex uint64, blockHash types.Hash) (types.H256, types.MMRLeaf, [][]byte, error) {
	resp, err := conn.RPC.MMR.GenerateProof(leafIndex, blockHash)
	if err != nil {
		return types.H256{}, types.MMRLeaf{}, nil, err
	}

	retBlockHash, mmrLeaf, proof := resp.BlockHash, resp.Leaf, resp.Proof
	log.Printf("\nLeafIndex:%d\nGenerated MMR Proof: %+v", leafIndex, resp)
	var mmrLeafProof = make([][]byte, len(proof.Items))
	for i := 0; i < len(proof.Items); i++ {
		mmrLeafProof[i] = proof.Items[i][:]
	}

	return retBlockHash, mmrLeaf, mmrLeafProof, nil

}

func VerifyMMRProof(sc types.SignedCommitment, mmrSize uint64, leafIndex uint64, mmrLeaf types.MMRLeaf, mmrLeafProof [][]byte) (bool, error) {
	// TODO: check the parameters

	for _, payload := range sc.Commitment.Payload {
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

			//TODO: encoded again for testing
			mmrLeafBytes, err := codec.Encode(encodedMMRLeaf)
			if err != nil {
				return false, err
			}
			log.Printf("mmrLeafBytes: %#x", mmrLeafBytes)

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

			//TODO: test for mmrLeafBytes leaf
			mmrLeaves2 := []merkletypes.Leaf{
				{
					Hash:  crypto.Keccak256(mmrLeafBytes),
					Index: leafIndex,
				},
			}
			mmrProof2 := mmr.NewProof(mmrSize, mmrLeafProof, mmrLeaves2, hasher.Keccak256Hasher{})
			// if !mmrProof2.Verify(payload.Data) {
			// 	return false, err
			// }
			calMMRRoot2, err := mmrProof2.CalculateRoot()
			if err != nil {
				return false, err
			}
			log.Printf("cal mmr root2:%#x\n ", calMMRRoot2)
			log.Printf("payload.Data:%#x\n ", payload.Data)
			ret = reflect.DeepEqual(calMMRRoot2, payload.Data)
			log.Printf("reflect.DeepEqual result :%#v", ret)

			break
		}
	}

	return true, nil

}
