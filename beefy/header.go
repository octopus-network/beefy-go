package beefy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"reflect"
	"sort"

	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/merkle"
	"github.com/ComposableFi/go-merkle-trees/mmr"
	merkletypes "github.com/ComposableFi/go-merkle-trees/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/hash"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
	"github.com/ethereum/go-ethereum/crypto"
)

// chain type
const (
	CHAINTYPE_SOLOCHAIN uint32 = 0
	CHAINTYPE_PARACHAIN uint32 = 1
)

type SolochainHeader struct {
	// scale-encoded parachain header bytes
	BlockHeader []byte `protobuf:"bytes,1,opt,name=solochain_header,json=solochainHeader,proto3" json:"solochain_header,omitempty"`
	// timestamp and proof
	// Timestamp Timestamp `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp"`
	Timestamp StateProof `protobuf:"bytes,2,opt,name=timestamp,proto3" json:"timestamp"`
}

/// Parachain headers and their merkle proofs.
type ParachainHeaders struct {
	// map<blocknumber,ParachainHeader>
	ParachainHeaderMap map[uint32]*ParachainHeader `json:"parachain_header_map,omitempty"`
}

// data needed to prove parachain header inclusion in mmr
type ParachainHeader struct {
	ParaId uint32 `json:"para_id,omitempty"`
	// scale-encoded parachain header bytes
	BlockHeader []byte `json:"parachain_header,omitempty"`
	// proofs for parachain header in the mmr_leaf.parachain_heads
	Proof [][]byte `json:"proof,omitempty"`
	// merkle leaf index for parachain heads proof
	HeaderIndex uint32 `json:"head_index,omitempty"`
	// total number of para heads in parachain_heads_root
	HeaderCount uint32 `json:"head_count,omitempty"`
	// timestamp and proof
	// Timestamp Timestamp `json:"timestamp,omitempty"`
	Timestamp StateProof `json:"timestamp,omitempty"`
}

type ParaIdAndHeader struct {
	ParaId uint32
	Header []byte
}

func GetParachainIds(conn *gsrpc.SubstrateAPI, blockHash types.Hash) ([]uint32, error) {
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
		return nil, fmt.Errorf("paraids not found")
	}

	return paraIds, nil
}

func GetParachainHeader(conn *gsrpc.SubstrateAPI, paraId uint32, blockHash types.Hash) ([]byte, error) {
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

func QueryParachainStorage(conn *gsrpc.SubstrateAPI, targetParaID uint32, fromHash types.Hash, toHash types.Hash) ([]types.StorageChangeSet, error) {

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
func BuildRelaychainHeaderMap(conn *gsrpc.SubstrateAPI, blockHash types.Hash, changeSet []types.StorageChangeSet) (map[uint32]map[uint32][]byte, []uint64, error) {

	var relayerHeaderMap = make(map[uint32]map[uint32][]byte)
	// all the leaf index for relay chain header
	var relayChainHeaderIdxes []uint64

	paraIds, err := GetParachainIds(conn, blockHash)
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
			paraChainHeader, err := GetParachainHeader(conn, paraId, changes.Block)
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
		log.Printf("relayChainHeader.Number: %d relayerLeafIndex: %d", relayChainHeader.Number, relayerHeaderIndex)
		relayChainHeaderIdxes = append(relayChainHeaderIdxes, relayerHeaderIndex)
	}
	return relayerHeaderMap, relayChainHeaderIdxes, nil

}

// type ParaHeaderWithProof struct {
// 	// scale-encoded parachain header bytes
// 	ParachainHeader []byte `protobuf:"bytes,1,opt,name=parachain_header,json=parachainHeader,proto3" json:"parachain_header,omitempty"`
// 	// reconstructed MmrLeaf, see beefy-go spec
// 	MmrLeafPartial BeefyMmrLeafPartial `protobuf:"bytes,2,opt,name=mmr_leaf_partial,json=mmrLeafPartial,proto3" json:"mmr_leaf_partial,omitempty"`
// 	// para_id of the header.
// 	ParaId uint32 `protobuf:"varint,3,opt,name=para_id,json=paraId,proto3" json:"para_id,omitempty"`
// 	// proofs for our header in the parachain heads root
// 	ParachainHeadsProof [][]byte `protobuf:"bytes,4,rep,name=parachain_heads_proof,json=parachainHeadsProof,proto3" json:"parachain_heads_proof,omitempty"`
// 	// leaf index for parachain heads proof
// 	HeadsLeafIndex uint32 `protobuf:"varint,5,opt,name=heads_leaf_index,json=headsLeafIndex,proto3" json:"heads_leaf_index,omitempty"`
// 	// total number of para heads in parachain_heads_root
// 	HeadsTotalCount uint32 `protobuf:"varint,6,opt,name=heads_total_count,json=headsTotalCount,proto3" json:"heads_total_count,omitempty"`
// 	// trie merkle proof of inclusion in header.extrinsic_root
// 	ExtrinsicProof [][]byte `protobuf:"bytes,7,rep,name=extrinsic_proof,json=extrinsicProof,proto3" json:"extrinsic_proof,omitempty"`
// 	// the actual timestamp extrinsic
// 	TimestampExtrinsic []byte `protobuf:"bytes,8,opt,name=timestamp_extrinsic,json=timestampExtrinsic,proto3" json:"timestamp_extrinsic,omitempty"`
// }
// type BeefyMmrLeafPartial struct {
// 	// leaf version
// 	Version U8 `protobuf:"varint,1,opt,name=version,proto3,customtype=U8" json:"version"`
// 	// parent block for this leaf
// 	ParentNumber uint32 `protobuf:"varint,2,opt,name=parent_number,json=parentNumber,proto3" json:"parent_number,omitempty"`
// 	// parent hash for this leaf
// 	ParentHash SizedByte32 `protobuf:"bytes,3,opt,name=parent_hash,json=parentHash,proto3,customtype=SizedByte32" json:"parent_hash,omitempty"`
// 	// next authority set.
// 	BeefyNextAuthoritySet BeefyAuthoritySet `protobuf:"bytes,4,opt,name=beefy_next_authority_set,json=beefyNextAuthoritySet,proto3" json:"beefy_next_authority_set"`
// }

func BuildParachainHeaderProof(conn *gsrpc.SubstrateAPI, blockHash types.Hash,
	mmrBatchProof MmrProofsResp,
	relayerHeaderMap map[uint32]map[uint32][]byte,
	targetParaId uint32) ([]ParachainHeader, error) {

	var targetParaHeaderWithProofs []ParachainHeader
	proofCount := len(mmrBatchProof.Leaves)
	for i := 0; i < proofCount; i++ {

		relayerLeafWithIdx := MMRLeafWithIndex{Leaf: mmrBatchProof.Leaves[i], Index: uint64(mmrBatchProof.Proof.LeafIndexes[i])}
		log.Printf("idxedLeaf: %+v", relayerLeafWithIdx)
		var leafBlockNumber = ConvertMmrLeafIndexToBlockNumber(BEEFY_ACTIVATION_BLOCK, uint32(relayerLeafWithIdx.Index))
		// var leafBlockNumber = uint32(relayerLeafWithIdx.Index)
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
		// authorityRoot := Bytes32(relayerLeafWithIdx.Leaf.BeefyNextAuthoritySet.Root[:])
		// parentHash := Bytes32(relayerLeafWithIdx.Leaf.ParentNumberAndHash.Hash[:])
		headsTotalCount := uint32(len(paraHeaderLeaves))
		log.Printf("headsTotalCount: %d", headsTotalCount)

		targetParaHeaderWithProof := ParachainHeader{
			BlockHeader: paraHeaderMap[targetParaId],

			Proof: paraHeadsProof.ProofHashes(),
			// ParaId:              targetParaId,
			HeaderIndex: index,
			HeaderCount: headsTotalCount,
		}

		targetParaHeaderWithProofs = append(targetParaHeaderWithProofs, targetParaHeaderWithProof)
	}
	return targetParaHeaderWithProofs, nil
}

// type BeefyMmrLeaf struct {
// 	// leaf version
// 	Version U8 `protobuf:"varint,1,opt,name=version,proto3,customtype=U8" json:"version"`
// 	// parent block for this leaf
// 	ParentNumber uint32 `protobuf:"varint,2,opt,name=parent_number,json=parentNumber,proto3" json:"parent_number,omitempty"`
// 	// parent hash for this leaf
// 	ParentHash SizedByte32 `protobuf:"bytes,3,opt,name=parent_hash,json=parentHash,proto3,customtype=SizedByte32" json:"parent_hash,omitempty"`
// 	// beefy next authority set.
// 	BeefyNextAuthoritySet BeefyAuthoritySet `protobuf:"bytes,4,opt,name=beefy_next_authority_set,json=beefyNextAuthoritySet,proto3" json:"beefy_next_authority_set"`
// 	// merkle root hash of parachain heads included in the leaf.
// 	ParachainHeads SizedByte32 `protobuf:"bytes,5,opt,name=parachain_heads,json=parachainHeads,proto3,customtype=SizedByte32" json:"parachain_heads,omitempty"`
// }

func BuildMMRProofFromParaHeaders(paraHeaderWithProofs []ParachainHeader, mmrSize uint64, mmrBatchProof MmrProofsResp) (*mmr.Proof, error) {

	paraHeadProofsLen := len(paraHeaderWithProofs)
	log.Printf("proofsLen: %d", paraHeadProofsLen)
	mmrLeaves := make([]merkletypes.Leaf, paraHeadProofsLen)

	// verify parachain headers
	for i := 0; i < paraHeadProofsLen; i++ {
		// reconstruct the mmr leaf for this header
		paraHeaderWithProof := paraHeaderWithProofs[i]
		log.Printf("paraHeaderProof: %+v", paraHeaderWithProof)
		encodedParaHead, err := codec.Encode(ParaIdAndHeader{ParaId: paraHeaderWithProof.ParaId, Header: paraHeaderWithProof.BlockHeader})
		if err != nil {
			return nil, err
		}
		headLeaf := []merkletypes.Leaf{
			{
				Index: uint64(paraHeaderWithProof.HeaderIndex),
				Hash:  crypto.Keccak256(encodedParaHead),
			},
		}
		log.Printf("paraHeaderProof.HeadsTotalCount: %d", paraHeaderWithProof.HeaderCount)
		//build merkle proof from para chain header proof
		paraHeadMerkleProof := merkle.NewProof(headLeaf, paraHeaderWithProof.Proof, uint64(paraHeaderWithProof.HeaderCount), hasher.Keccak256Hasher{})
		// TODO: merkle.Proof.Root() should return fixed bytes
		paraHeadersMerkleRoot, err := paraHeadMerkleProof.Root()
		log.Printf("parachainHeadsRoot: %#x", paraHeadersMerkleRoot)

		if err != nil {
			return nil, err
		}

		var parachainHeads SizedByte32
		copy(parachainHeads[:], paraHeadersMerkleRoot)

		// mmrLeaf := BeefyMmrLeaf{
		// 	Version:      paraHeaderWithProof.MmrLeafPartial.Version,
		// 	ParentNumber: paraHeaderWithProof.MmrLeafPartial.ParentNumber,
		// 	ParentHash:   paraHeaderWithProof.MmrLeafPartial.ParentHash,
		// 	BeefyNextAuthoritySet: BeefyAuthoritySet{
		// 		Id:   paraHeaderWithProof.MmrLeafPartial.BeefyNextAuthoritySet.Id,
		// 		Len:  paraHeaderWithProof.MmrLeafPartial.BeefyNextAuthoritySet.Len,
		// 		Root: paraHeaderWithProof.MmrLeafPartial.BeefyNextAuthoritySet.Root,
		// 	},
		// 	ParachainHeads: parachainHeads,
		// }
		// log.Printf("mmrLeaf: %+v", mmrLeaf)
		// the mmr leaf's are a scale-encoded
		// encodedMMRLeaf, err := codec.Encode(mmrLeaf)
		// if err != nil {
		// 	return nil, err
		// }

		// mmrLeaves[i] = merkletypes.Leaf{
		// 	// based on our knowledge of the beefy protocol, and the structure of MMRs
		// 	// we are be able to reconstruct the leaf index of this mmr leaf
		// 	// given the parent_number of this leaf, the beefy activation block
		// 	// Index: uint64(GetLeafIndexForBlockNumber(BEEFY_ACTIVATION_BLOCK, paraHeaderWithProof.MmrLeafPartial.ParentNumber+1)),
		// 	Index: uint64(mmrBatchProof.Proof.LeafIndex[i]),
		// 	Hash:  crypto.Keccak256(encodedMMRLeaf),
		// }
	}

	// convert proof items
	var mmrBatchProofItems = make([][]byte, len(mmrBatchProof.Proof.Items))
	for i := 0; i < len(mmrBatchProof.Proof.Items); i++ {
		mmrBatchProofItems[i] = mmrBatchProof.Proof.Items[i][:]
	}
	// log.Printf("mmrBatchProof Proof Items count: %d", len(mmrBatchProofItems))
	// for _, item := range mmrBatchProofItems {
	// 	log.Printf("mmrBatchProof Proof Item: %#x", item)
	// }
	// build mmr proof from mmr leaves
	mmrProof := mmr.NewProof(mmrSize, mmrBatchProofItems, mmrLeaves, hasher.Keccak256Hasher{})

	return mmrProof, nil
}

func BuildSolochainHeaderMap(conn *gsrpc.SubstrateAPI, leafIndexes []types.U64) (map[uint32]SolochainHeader, error) {
	leafNum := len(leafIndexes)
	solochainHeaderMap := make(map[uint32]SolochainHeader)
	for i := 0; i < leafNum; i++ {
		solochainBlockNumber := uint64(leafIndexes[i])
		solochainBlockHash, err := conn.RPC.Chain.GetBlockHash(solochainBlockNumber)
		if err != nil {
			return nil, err
		}
		blockHeader, err := conn.RPC.Chain.GetHeader(solochainBlockHash)
		if err != nil {
			return nil, err
		}
		// t.Logf("solochainHeader: %+v", blockHeader)
		ecodedHeader, err := codec.Encode(blockHeader)
		if err != nil {
			return nil, err
		}

		//  get timestamp and proof
		timestamp, err := BuildTimestampProof(conn, solochainBlockHash)
		if err != nil {
			return nil, err
		}
		log.Printf("timestamp: %+v", timestamp)

		// build SolochainHeader
		// solochainBlockHashBytes, err = beefy.Bytes32(solochainBlockHash).Marshal()
		// require.NoError(t, err)
		// solochainHeaderMap[uint32(solochainBlockNumber)] = solochainBlockHash[:]
		solochainHeader := SolochainHeader{
			BlockHeader: ecodedHeader,
			Timestamp:   timestamp,
		}

		solochainHeaderMap[uint32(solochainBlockNumber)] = solochainHeader

	}
	return solochainHeaderMap, nil
}

//verify solochain header with proofs
func VerifySolochainHeader(leaves []types.MMRLeaf, solochainHeaderMap map[uint32]SolochainHeader) error {

	//step1:verify solochain header
	//the leaf parent hash == blake2b256(scale.encode(solochain header))
	// leafNum := len(leaves)
	for _, leaf := range leaves {
		solochainHeader := solochainHeaderMap[uint32(leaf.ParentNumberAndHash.ParentNumber)]
		blake2b256, err := hash.NewBlake2b256(nil)
		if err != nil {
			return err
		}
		_, err = blake2b256.Write(solochainHeader.BlockHeader)
		headHash := blake2b256.Sum(nil)
		if err != nil {
			return err
		}
		log.Printf("leaf.ParentNumberAndHash.ParentNumber: %d", leaf.ParentNumberAndHash.ParentNumber)
		log.Printf("mmrLeaf parent Hash: %#x", leaf.ParentNumberAndHash.Hash)
		log.Printf("solochainHeader.blockHeader blake2b256 hash: %#x", headHash)
		ret := reflect.DeepEqual(headHash, leaf.ParentNumberAndHash.Hash[:])

		if !ret {

			return errors.New("failure to verify solochain header")
		}

		//step2:verify timestamp and proof
		//decode header
		var decodeParachainHeader types.Header
		err = codec.Decode(solochainHeader.BlockHeader, &decodeParachainHeader)
		if err != nil {
			return err
		}
		log.Printf("solochain BlockNumber: %d", decodeParachainHeader.Number)
		log.Printf("decodeParachainHeader.StateRoot: %#x", decodeParachainHeader.StateRoot)
		log.Printf("-------------- verify timestamp proof ---------------")
		err = VerifyStateProof(solochainHeader.Timestamp.Proofs, decodeParachainHeader.StateRoot[:], solochainHeader.Timestamp.Key, solochainHeader.Timestamp.Value)
		log.Printf("VerifyStateProof(solochainHeader.Timestamp.Proofs, decodeParachainHeader.StateRoot[:], timestampKey, value) result: %+v", ret)
		if err != nil {
			return err
		}

	}

	return nil

}

//build parachain header map
func BuildParachainHeaderMap(relaychainEndpoint *gsrpc.SubstrateAPI, parachainEndpoint *gsrpc.SubstrateAPI,
	leafIndexes []types.U64, targetParachainId uint32) (map[uint32]ParachainHeader, error) {
	leafNum := len(leafIndexes)
	parachainHeaderMap := make(map[uint32]ParachainHeader)

	for i := 0; i < leafNum; i++ {
		targetLeafIndex := uint64(leafIndexes[i])
		targetLeafBlockHash, err := relaychainEndpoint.RPC.Chain.GetBlockHash(targetLeafIndex)
		if err != nil {
			return nil, err
		}
		log.Printf("targetLeafIndex: %d targetLeafBlockHash: %#x", targetLeafIndex, targetLeafBlockHash)
		paraChainIds, err := GetParachainIds(relaychainEndpoint, targetLeafBlockHash)
		if err != nil {
			return nil, err
		}
		log.Printf("parachainIds: %+v", paraChainIds)
		var encodedheaderMap = make(map[uint32][]byte, len(paraChainIds))
		//find relayer header that includes all the target parachain header
		for _, parachainId := range paraChainIds {
			encodedHeader, err := GetParachainHeader(relaychainEndpoint, uint32(parachainId), targetLeafBlockHash)
			if err != nil {
				return nil, err
			}
			// t.Logf("paraChainId: %d", paraChainId)
			log.Printf("parachainId: %d parachainHeader: %#x", parachainId, encodedHeader)
			encodedheaderMap[parachainId] = encodedHeader
		}
		log.Printf("paraChainHeaderMap: %+v", encodedheaderMap)
		// sort by paraId
		var sortedParachainIds []uint32
		for parachainId := range encodedheaderMap {
			sortedParachainIds = append(sortedParachainIds, parachainId)
		}
		sort.SliceStable(sortedParachainIds, func(i, j int) bool {
			return sortedParachainIds[i] < sortedParachainIds[j]
		})
		log.Printf("sortedParaIds: %+v", sortedParachainIds)

		var parachainHeaderLeaves [][]byte
		var targetHeaderIndex uint32

		count := 0
		for _, parachainId := range sortedParachainIds {
			encodedParaHeader, err := codec.Encode(ParaIdAndHeader{
				ParaId: parachainId,
				Header: encodedheaderMap[parachainId]})
			if err != nil {
				return nil, err
			}
			// get parachainheader Keccak256 hash
			parachainHeaderLeaf := crypto.Keccak256(encodedParaHeader)
			parachainHeaderLeaves = append(parachainHeaderLeaves, parachainHeaderLeaf)
			if parachainId == targetParachainId {
				// find the index of target parachain id
				targetHeaderIndex = uint32(count)
				log.Printf("targetHeaderIndex: %d", targetHeaderIndex)
			}
			count++
		}
		log.Printf("parachainHeaderLeaves: %+v", parachainHeaderLeaves)
		// build merkle tree from all the paraheader leaves
		tree, err := merkle.NewTree(hasher.Keccak256Hasher{}).FromLeaves(parachainHeaderLeaves)
		if err != nil {
			return nil, err
		}

		// build merkle tree from target parachain proof
		targetParachainHeader := encodedheaderMap[targetParachainId]
		targetParachainHeaderTree := tree.Proof([]uint64{uint64(targetHeaderIndex)})
		log.Printf("targetParachainHeaderTree: %+v", targetParachainHeaderTree)
		targetParachainHeaderProof := targetParachainHeaderTree.ProofHashes()
		log.Printf("targetParachainHeaderProof: %+v", targetParachainHeaderProof)
		parachainHeaderTotalCount := uint32(len(parachainHeaderLeaves))

		//  get timestamp and proof
		var decodeParachainHeader types.Header
		err = codec.Decode(targetParachainHeader, &decodeParachainHeader)
		if err != nil {
			return nil, err
		}
		log.Printf("parachain BlockNumber: %d", decodeParachainHeader.Number)
		log.Printf("decodeParachainHeader.StateRoot: %#x", decodeParachainHeader.StateRoot)

		// switch to parachain endpoint
		// parachainEndpoint, err := gsrpc.NewSubstrateAPI(LOCAL_PARACHAIN_ENDPOINT)
		if err != nil {
			return nil, err
		}
		blockHash, err := parachainEndpoint.RPC.Chain.GetBlockHash(uint64(decodeParachainHeader.Number))
		if err != nil {
			return nil, err
		}
		log.Printf("parachain blockHash: %#x ", blockHash)

		timestamp, err := BuildTimestampProof(parachainEndpoint, blockHash)
		if err != nil {
			return nil, err
		}
		log.Printf("timestamp: %+v", timestamp)

		parachainHeader := ParachainHeader{
			ParaId:      targetParachainId,
			BlockHeader: targetParachainHeader,
			Proof:       targetParachainHeaderProof,
			HeaderIndex: targetHeaderIndex,
			HeaderCount: parachainHeaderTotalCount,
			Timestamp:   timestamp,
		}
		parachainHeaderMap[uint32(targetLeafIndex)] = parachainHeader
	}

	return parachainHeaderMap, nil
}

//verify parachain header with proofs
func VerifyParachainHeader(leaves []types.MMRLeaf, ParachainHeaderMap map[uint32]ParachainHeader) error {

	//step1:verify parachain header
	for _, leaf := range leaves {
		parachainHeader := ParachainHeaderMap[uint32(leaf.ParentNumberAndHash.ParentNumber)]
		encodedParachainHeader, err := codec.Encode(ParaIdAndHeader{ParaId: parachainHeader.ParaId, Header: parachainHeader.BlockHeader})
		if err != nil {
			return err
		}

		targetParaHeaderLeaves := []merkletypes.Leaf{
			{
				Hash:  crypto.Keccak256(encodedParachainHeader),
				Index: uint64(parachainHeader.HeaderIndex),
			},
		}
		parachainHeadsProof := merkle.NewProof(targetParaHeaderLeaves, parachainHeader.Proof,
			uint64(parachainHeader.HeaderCount), hasher.Keccak256Hasher{})

		// TODO: constraint condition: merkle.Proof.Root() should return fixed bytes
		// get merkle root
		parachainHeadsRoot, err := parachainHeadsProof.Root()
		if err != nil {
			return err
		}

		// verify new merkle root == mmrLeafParachainHeads
		log.Printf("------------------------------------------------------------------------------------")
		log.Printf("leaf.ParentNumberAndHash.ParentNumber: %d", leaf.ParentNumberAndHash.ParentNumber)
		log.Printf("parachain blockNumber: %d", leaf.ParentNumberAndHash.ParentNumber)
		log.Printf("leaf.ParachainHeads: %#x", leaf.ParachainHeads)
		log.Printf("cal parachainHeadsRoot: %#x", parachainHeadsRoot)
		log.Printf("------------------------------------------------------------------------------------")
		ret := reflect.DeepEqual(parachainHeadsRoot, leaf.ParachainHeads[:])
		if !ret {

			return errors.New("failure to verify parachain header")
		}

		//verify timestamp proof
		//decode parachain header
		var decodeParachainHeader types.Header
		err = codec.Decode(parachainHeader.BlockHeader, &decodeParachainHeader)
		if err != nil {
			return err
		}
		log.Printf("parachain BlockNumber: %d", decodeParachainHeader.Number)
		log.Printf("decodeParachainHeader.StateRoot: %#x", decodeParachainHeader.StateRoot)

		err = VerifyStateProof(parachainHeader.Timestamp.Proofs, decodeParachainHeader.StateRoot[:], parachainHeader.Timestamp.Key, parachainHeader.Timestamp.Value)
		log.Printf("VerifyStateProof(parachainHeader.Timestamp.Proofs, decodeParachainHeader.StateRoot[:], timestampKey, value) result: %+v", ret)
		if err != nil {
			return err
		}

	}

	return nil

}
