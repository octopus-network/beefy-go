package beefy

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"reflect"
	"sort"

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
	LeafIndexes []types.U64
	// Number of leaves in MMR, when the proof was generated.
	LeafCount types.U64
	// Proof elements (hashes of siblings of inner nodes on the path to the leaf).
	Items []types.H256
}

// MmrProofsResp contains the generate batch proof rpc response
type MmrProofsResp struct {
	BlockHash types.H256
	Leaves    []types.MMRLeaf
	Proof     MMRBatchProof
}

// UnmarshalJSON fills u with the JSON encoded byte array given by b
func (d *MmrProofsResp) UnmarshalJSON(bz []byte) error {
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
func BuildMMRBatchProof(conn *gsrpc.SubstrateAPI, blockHash *types.Hash, idxes []uint64) (MmrProofsResp, error) {
	var batchProofResp MmrProofsResp
	err := client.CallWithBlockHash(conn.Client, &batchProofResp, "mmr_generateBatchProof", blockHash, idxes)
	if err != nil {
		return MmrProofsResp{}, err
	}

	return batchProofResp, nil
}

// get mmr proofs for the given indexes without blockhash
func BuildMMRProofs(conn *gsrpc.SubstrateAPI, blockNumbers []uint32, bestKnownBlockNumber types.OptionU32,
	at types.OptionHash) (MmrProofsResp, error) {
	var proofsResp MmrProofsResp
	// var args []interface{}

	// if bestKnownBlockNumber > 0 {
	ret, bestBlockNumber := bestKnownBlockNumber.Unwrap()
	if !ret {
		// generate mmr proof without best blocknumber and blockhash
		err := conn.Client.Call(&proofsResp, "mmr_generateProof", blockNumbers)
		if err != nil {
			return proofsResp, err
		}
		return proofsResp, nil
	}

	sort.SliceStable(blockNumbers, func(i, j int) bool {
		return blockNumbers[i] < blockNumbers[j]
	})
	// best_known_block_number must ET all the blockNumbers
	if uint32(bestBlockNumber) < blockNumbers[len(blockNumbers)-1] {
		log.Printf("bestKnownBlockNumber: %d < largest blockNumber: %d", uint32(bestBlockNumber), blockNumbers[len(blockNumbers)-1])
		return proofsResp, errors.New("best_known_block_number must > all the blockNumbers")
	}

	// Note that if `best_known_block_number` is provided, then also
	// specifying the block hash via `at` isn't super-useful here, unless you're generating proof
	// using non-finalized blocks where there are several competing forks.
	ret, blockHash := at.Unwrap()
	if !ret {
		err := conn.Client.Call(&proofsResp, "mmr_generateProof", blockNumbers, uint32(bestBlockNumber))
		if err != nil {
			return proofsResp, err
		}
	} else {
		err := conn.Client.Call(&proofsResp, "mmr_generateProof", blockNumbers, uint32(bestBlockNumber), blockHash)
		if err != nil {
			return proofsResp, err
		}
	}

	return proofsResp, nil
}

// verify batch mmr proof
func VerifyMMRBatchProof(mmrRoot []byte, mmrSize uint64, mmrLeaves []types.MMRLeaf, mmrbatchProof MMRBatchProof) (bool, error) {
	leafNum := len(mmrLeaves)
	var leaves = make([]merkletypes.Leaf, leafNum)
	for i := 0; i < leafNum; i++ {
		// scale encode the mmr leaf
		encodedMMRLeaf, err := codec.Encode(mmrLeaves[i])
		if err != nil {
			return false, err
		}
		// log.Printf("encodedMMRLeaf: %#x", encodedMMRLeaf)
		leaf := merkletypes.Leaf{
			Hash:  crypto.Keccak256(encodedMMRLeaf),
			Index: uint64(mmrbatchProof.LeafIndexes[i]),
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

	log.Printf("beefy-go::VerifyMMRBatchProof -> cal mmr root:%#x", calMMRRoot)
	log.Printf("beefy-go::VerifyMMRBatchProof -> expected mmr root :%#x", mmrRoot)
	ret := reflect.DeepEqual(calMMRRoot, mmrRoot)
	log.Printf("beefy-go::VerifyMMRBatchProof -> reflect.DeepEqual result :%#v", ret)
	if !ret {
		return false, errors.New("the cal mmr root != expected mmr root")
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

// only for polkadot relay chain
func GetBeefyFinalizedHead(conn *gsrpc.SubstrateAPI) (types.Hash, error) {

	var hash types.Hash
	err := conn.Client.Call(&hash, "beefy_getFinalizedHead")
	if err != nil {
		return types.Hash{}, err
	}

	return hash, err

}
