package beefy

import (
	"encoding/binary"
	"fmt"
	"log"
	"sort"

	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/merkle"
	"github.com/ComposableFi/go-merkle-trees/mmr"
	merkletypes "github.com/ComposableFi/go-merkle-trees/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
	"github.com/ethereum/go-ethereum/crypto"
)

type ParaIdAndHeader struct {
	ParaId uint32
	Header []byte
}

func GetParaChainIDs(conn *gsrpc.SubstrateAPI, blockHash types.Hash) ([]uint32, error) {
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

func GetParaChainHeader(conn *gsrpc.SubstrateAPI, paraId uint32, blockHash types.Hash) ([]byte, error) {
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

func QueryParaChainStorage(conn *gsrpc.SubstrateAPI, targetParaID uint32, fromHash types.Hash, toHash types.Hash) ([]types.StorageChangeSet, error) {

	log.Printf("target parachian id : %d", targetParaID)
	var paraHeaderKeys []types.StorageKey

	// create full storage key for target paraId
	keyPrefix := CreateStorageKeyPrefix("Paras", "Heads")
	log.Printf("keyPrefix: %#x", keyPrefix)
	encodedParaID, err := codec.Encode(targetParaID)
	log.Printf("encodedParaID: %#x", encodedParaID)
	if err != nil {
		return nil, err
	}

	twoXHash := xxhash.New64(encodedParaID).Sum(nil)
	log.Printf("encodedParaID twoXHash: %#x", twoXHash)
	// full key path in the storage source: https://www.shawntabrizi.com/assets/presentations/substrate-storage-deep-dive.pdf
	// xx128("Paras") + xx128("Heads") + xx64(Encode(paraId)) + Encode(paraId)
	fullKey := append(append(keyPrefix, twoXHash[:]...), encodedParaID...)
	log.Printf("fullKey: %#x", fullKey)
	paraHeaderKeys = append(paraHeaderKeys, fullKey)

	changeSets, err := conn.RPC.State.QueryStorage(paraHeaderKeys, fromHash, toHash)
	if err != nil {
		return nil, err
	}

	return changeSets, nil
}

// RelayerHeaderMap<RelayerChainBlockNumber, ParaChainHeaderMap<ParaId, Header>>
// double map that holds block numbers, for which parachain headerwas included in the mmr leaf
// find all the para chain headers that filted by changeset
func BuildRelayerHeaderMap(conn *gsrpc.SubstrateAPI, blockHash types.Hash, changeSet []types.StorageChangeSet) (map[uint32]map[uint32][]byte, []uint64, error) {

	var relayerHeaderMap = make(map[uint32]map[uint32][]byte)
	// request for batch mmr proof of those leaves
	var relayChainHeaderIdxes []uint64

	paraIds, err := GetParaChainIDs(conn, blockHash)
	log.Printf("paraIds: %+v at relayerchain block: %#x", paraIds, blockHash)
	if err != nil {
		return nil, nil, err
	}

	for _, changes := range changeSet {
		relayChainHeader, err := conn.RPC.Chain.GetHeader(changes.Block)
		if err != nil {
			return nil, nil, err
		}
		// paraChainHeaderMap<ParaId, Header>>
		var paraChainHeaderMap = make(map[uint32][]byte)

		for _, paraId := range paraIds {
			// TODO: check: the parachain header maybe not exist at changes.block
			// So, the best way is continue to next paraId but not return
			paraChainHeader, err := GetParaChainHeader(conn, paraId, changes.Block)
			if err != nil {
				log.Printf("paraId: %d \n parachain header not found !", paraId)
				continue
			}
			paraChainHeaderMap[paraId] = paraChainHeader
			log.Printf("paraId: %d \n paraChainHeader: %#x", paraId, paraChainHeader)
			// log.Printf("paraChainHeaderMap: %+v", paraChainHeaderMap)
		}
		relayerHeaderMap[uint32(relayChainHeader.Number)] = paraChainHeaderMap
		log.Printf("relayChainHeader.Number: %d \n relayerHeaderMap: %+v", relayChainHeader.Number, relayerHeaderMap)

		// relayerHeaderIndex := uint64(GetLeafIndexForBlockNumber(BEEFY_ACTIVATION_BLOCK, uint32(relayChainHeader.Number)))
		relayerHeaderIndex := uint64(relayChainHeader.Number)
		log.Printf("relayChainHeader.Number: %d relayerHeaderIndex: %d", relayChainHeader.Number, relayerHeaderIndex)
		relayChainHeaderIdxes = append(relayChainHeaderIdxes, relayerHeaderIndex)
	}
	return relayerHeaderMap, relayChainHeaderIdxes, nil

}

type ParaHeaderWithProof struct {
	// scale-encoded parachain header bytes
	ParachainHeader []byte `protobuf:"bytes,1,opt,name=parachain_header,json=parachainHeader,proto3" json:"parachain_header,omitempty"`
	// reconstructed MmrLeaf, see beefy-go spec
	MmrLeafPartial BeefyMmrLeafPartial `protobuf:"bytes,2,opt,name=mmr_leaf_partial,json=mmrLeafPartial,proto3" json:"mmr_leaf_partial,omitempty"`
	// para_id of the header.
	ParaId uint32 `protobuf:"varint,3,opt,name=para_id,json=paraId,proto3" json:"para_id,omitempty"`
	// proofs for our header in the parachain heads root
	ParachainHeadsProof [][]byte `protobuf:"bytes,4,rep,name=parachain_heads_proof,json=parachainHeadsProof,proto3" json:"parachain_heads_proof,omitempty"`
	// leaf index for parachain heads proof
	HeadsLeafIndex uint32 `protobuf:"varint,5,opt,name=heads_leaf_index,json=headsLeafIndex,proto3" json:"heads_leaf_index,omitempty"`
	// total number of para heads in parachain_heads_root
	HeadsTotalCount uint32 `protobuf:"varint,6,opt,name=heads_total_count,json=headsTotalCount,proto3" json:"heads_total_count,omitempty"`
	// trie merkle proof of inclusion in header.extrinsic_root
	ExtrinsicProof [][]byte `protobuf:"bytes,7,rep,name=extrinsic_proof,json=extrinsicProof,proto3" json:"extrinsic_proof,omitempty"`
	// the actual timestamp extrinsic
	TimestampExtrinsic []byte `protobuf:"bytes,8,opt,name=timestamp_extrinsic,json=timestampExtrinsic,proto3" json:"timestamp_extrinsic,omitempty"`
}
type BeefyMmrLeafPartial struct {
	// leaf version
	Version U8 `protobuf:"varint,1,opt,name=version,proto3,customtype=U8" json:"version"`
	// parent block for this leaf
	ParentNumber uint32 `protobuf:"varint,2,opt,name=parent_number,json=parentNumber,proto3" json:"parent_number,omitempty"`
	// parent hash for this leaf
	ParentHash SizedByte32 `protobuf:"bytes,3,opt,name=parent_hash,json=parentHash,proto3,customtype=SizedByte32" json:"parent_hash,omitempty"`
	// next authority set.
	BeefyNextAuthoritySet BeefyAuthoritySet `protobuf:"bytes,4,opt,name=beefy_next_authority_set,json=beefyNextAuthoritySet,proto3" json:"beefy_next_authority_set"`
}

func BuildTargetParaHeaderProof(conn *gsrpc.SubstrateAPI, blockHash types.Hash, mmrBatchProof GenerateMmrBatchProofResponse, relayerHeaderMap map[uint32]map[uint32][]byte, targetParaId uint32) ([]ParaHeaderWithProof, error) {

	var targetParaHeaderWithProofs []ParaHeaderWithProof
	proofCount := len(mmrBatchProof.Leaves)
	for i := 0; i < proofCount; i++ {

		relayerLeafWithIdx := LeafWithIndex{Leaf: mmrBatchProof.Leaves[i], Index: uint64(mmrBatchProof.Proof.LeafIndex[i])}
		log.Printf("idxedLeaf: %+v", relayerLeafWithIdx)
		var leafBlockNumber = GetBlockNumberForLeaf(BEEFY_ACTIVATION_BLOCK, uint32(relayerLeafWithIdx.Index))
		// var leafBlockNumber = uint32(idxedLeaf.Index)
		log.Printf("leaf index: %d leafBlockNumber: %d", relayerLeafWithIdx.Index, leafBlockNumber)
		paraHeaderMap := relayerHeaderMap[leafBlockNumber]
		log.Printf("relayer header number : %d  paraHeaderMap: %+v", leafBlockNumber, paraHeaderMap)

		var paraHeaderLeaves [][]byte
		// index of target parachain header in the
		// parachain heads merkle root
		var index uint32

		count := 0

		// sort by paraId
		var sortedParaIds []uint32
		for paraId := range paraHeaderMap {
			sortedParaIds = append(sortedParaIds, paraId)
		}
		sort.SliceStable(sortedParaIds, func(i, j int) bool {
			return sortedParaIds[i] < sortedParaIds[j]
		})
		log.Printf("sortedParaIds: %+v", sortedParaIds)

		for _, paraId := range sortedParaIds {
			encodedParaHeader, err := codec.Encode(ParaIdAndHeader{ParaId: paraId, Header: paraHeaderMap[paraId]})
			if err != nil {
				return nil, err
			}
			// get paraheader hash
			paraHeaderLeaf := crypto.Keccak256(encodedParaHeader)
			paraHeaderLeaves = append(paraHeaderLeaves, paraHeaderLeaf)
			if paraId == targetParaId {
				// find the index of targent para chain id
				index = uint32(count)
			}
			count++
		}
		log.Printf("paraHeadsLeaves: %+v", paraHeaderLeaves)
		// build merkle tree from all the paraheader leaves
		tree, err := merkle.NewTree(hasher.Keccak256Hasher{}).FromLeaves(paraHeaderLeaves)
		if err != nil {
			return nil, err
		}
		// generate proof for target parachain id
		paraHeadsProof := tree.Proof([]uint64{uint64(index)})
		authorityRoot := Bytes32(relayerLeafWithIdx.Leaf.BeefyNextAuthoritySet.Root[:])
		parentHash := Bytes32(relayerLeafWithIdx.Leaf.ParentNumberAndHash.Hash[:])
		headsTotalCount := uint32(len(paraHeaderLeaves))
		log.Printf("headsTotalCount: %d", headsTotalCount)

		targetParaHeaderWithProof := ParaHeaderWithProof{
			ParachainHeader: paraHeaderMap[targetParaId],
			MmrLeafPartial: BeefyMmrLeafPartial{
				Version:      U8(relayerLeafWithIdx.Leaf.Version),
				ParentNumber: uint32(relayerLeafWithIdx.Leaf.ParentNumberAndHash.ParentNumber),
				ParentHash:   parentHash,
				BeefyNextAuthoritySet: BeefyAuthoritySet{
					Id:   uint64(relayerLeafWithIdx.Leaf.BeefyNextAuthoritySet.ID),
					Len:  uint32(relayerLeafWithIdx.Leaf.BeefyNextAuthoritySet.Len),
					Root: authorityRoot,
				},
			},
			ParachainHeadsProof: paraHeadsProof.ProofHashes(),
			ParaId:              targetParaId,
			HeadsLeafIndex:      index,
			HeadsTotalCount:     headsTotalCount,
		}

		targetParaHeaderWithProofs = append(targetParaHeaderWithProofs, targetParaHeaderWithProof)
	}
	return targetParaHeaderWithProofs, nil
}

type BeefyMmrLeaf struct {
	// leaf version
	Version U8 `protobuf:"varint,1,opt,name=version,proto3,customtype=U8" json:"version"`
	// parent block for this leaf
	ParentNumber uint32 `protobuf:"varint,2,opt,name=parent_number,json=parentNumber,proto3" json:"parent_number,omitempty"`
	// parent hash for this leaf
	ParentHash SizedByte32 `protobuf:"bytes,3,opt,name=parent_hash,json=parentHash,proto3,customtype=SizedByte32" json:"parent_hash,omitempty"`
	// beefy next authority set.
	BeefyNextAuthoritySet BeefyAuthoritySet `protobuf:"bytes,4,opt,name=beefy_next_authority_set,json=beefyNextAuthoritySet,proto3" json:"beefy_next_authority_set"`
	// merkle root hash of parachain heads included in the leaf.
	ParachainHeads SizedByte32 `protobuf:"bytes,5,opt,name=parachain_heads,json=parachainHeads,proto3,customtype=SizedByte32" json:"parachain_heads,omitempty"`
}

func BuildMMRProofFromParaHeaders(paraHeaderWithProofs []ParaHeaderWithProof, mmrSize uint64, mmrProofs [][]byte) (*mmr.Proof, error) {
	paraHeadProofsLen := len(paraHeaderWithProofs)
	log.Printf("proofsLen: %d", paraHeadProofsLen)
	mmrLeaves := make([]merkletypes.Leaf, paraHeadProofsLen)

	// verify parachain headers
	for i := 0; i < paraHeadProofsLen; i++ {
		// reconstruct the mmr leaf for this header
		paraHeaderWithProof := paraHeaderWithProofs[i]
		log.Printf("paraHeaderProof: %+v", paraHeaderWithProof)
		encodedParaHead, err := codec.Encode(ParaIdAndHeader{ParaId: paraHeaderWithProof.ParaId, Header: paraHeaderWithProof.ParachainHeader})
		if err != nil {
			return nil, err
		}
		headLeaf := []merkletypes.Leaf{
			{
				Index: uint64(paraHeaderWithProof.HeadsLeafIndex),
				Hash:  crypto.Keccak256(encodedParaHead),
			},
		}
		log.Printf("paraHeaderProof.HeadsTotalCount: %d", paraHeaderWithProof.HeadsTotalCount)
		//build merkle proof from para chain header proof
		paraHeadMerkleProof := merkle.NewProof(headLeaf, paraHeaderWithProof.ParachainHeadsProof, uint64(paraHeaderWithProof.HeadsTotalCount), hasher.Keccak256Hasher{})
		// todo: merkle.Proof.Root() should return fixed bytes
		paraHeadersMerkleRoot, err := paraHeadMerkleProof.Root()
		log.Printf("parachainHeadsRoot: %#x", paraHeadersMerkleRoot)

		if err != nil {
			return nil, err
		}

		var parachainHeads SizedByte32
		copy(parachainHeads[:], paraHeadersMerkleRoot)

		mmrLeaf := BeefyMmrLeaf{
			Version:      paraHeaderWithProof.MmrLeafPartial.Version,
			ParentNumber: paraHeaderWithProof.MmrLeafPartial.ParentNumber,
			ParentHash:   paraHeaderWithProof.MmrLeafPartial.ParentHash,
			BeefyNextAuthoritySet: BeefyAuthoritySet{
				Id:   paraHeaderWithProof.MmrLeafPartial.BeefyNextAuthoritySet.Id,
				Len:  paraHeaderWithProof.MmrLeafPartial.BeefyNextAuthoritySet.Len,
				Root: paraHeaderWithProof.MmrLeafPartial.BeefyNextAuthoritySet.Root,
			},
			ParachainHeads: parachainHeads,
		}
		log.Printf("mmrLeaf: %+v", mmrLeaf)
		// the mmr leaf's are a scale-encoded
		encodedMMRLeaf, err := codec.Encode(mmrLeaf)
		if err != nil {
			return nil, err
		}

		mmrLeaves[i] = merkletypes.Leaf{
			// based on our knowledge of the beefy protocol, and the structure of MMRs
			// we are be able to reconstruct the leaf index of this mmr leaf
			// given the parent_number of this leaf, the beefy activation block
			Index: uint64(GetLeafIndexForBlockNumber(BEEFY_ACTIVATION_BLOCK, paraHeaderWithProof.MmrLeafPartial.ParentNumber+1)),
			Hash:  crypto.Keccak256(encodedMMRLeaf),
		}
	}

	// build mmr proof from mmr leaves
	mmrProof := mmr.NewProof(mmrSize, mmrProofs, mmrLeaves, hasher.Keccak256Hasher{})

	return mmrProof, nil
}

//TODO: verify parachain header proofs
func VerifyParaChainHeaderProofs() {}
