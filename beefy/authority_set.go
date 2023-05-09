package beefy

import (
	"fmt"
	"log"

	"github.com/ComposableFi/go-merkle-trees/hasher"
	"github.com/ComposableFi/go-merkle-trees/merkle"
	merkletypes "github.com/ComposableFi/go-merkle-trees/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types/codec"
	"github.com/ethereum/go-ethereum/crypto"
)

type Authorities = [][33]uint8

// type BeefyAuthoritySet struct {
// 	// Id of the authority set, it should be strictly increasing
// 	Id uint64 `json:"id,omitempty"`
// 	// Number of validators in the set.
// 	Len uint32 `json:"len,omitempty"`
// 	// Merkle Root Hash build from BEEFY uncompressed AuthorityIds.
// 	Root [32]byte
// 	// Root SizedByte32
// }

// Signature with it`s index in merkle tree
type Signature struct {
	// signature leaf index in the merkle tree.
	Index uint32 `json:"index,omitempty"`
	// signature bytes
	Signature []byte `json:"signature,omitempty"`
}

func GetBeefyAuthorities(blockHash types.Hash, api *gsrpc.SubstrateAPI, method string) ([][]byte, error) {

	// Fetch metadata
	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil, err
	}

	storageKey, err := types.CreateStorageKey(meta, "Beefy", method, nil, nil)
	if err != nil {
		return nil, err
	}

	var authorities Authorities

	ok, err := api.RPC.State.GetStorage(storageKey, &authorities, blockHash)
	if err != nil {
		return nil, err
	}

	if !ok {
		return nil, fmt.Errorf("beefy authorities not found")
	}
	log.Printf("authority count: %d\n", len(authorities))

	// Convert from ecdsa public key to ethereum address
	var authorityEthAddresses [][]byte
	for _, authority := range authorities {
		// log.Printf("authority pubkey: %s\n", codec.HexEncodeToString(authority[:]))
		pub, err := crypto.DecompressPubkey(authority[:])
		if err != nil {
			return nil, err
		}
		ethAddress := crypto.PubkeyToAddress(*pub)
		// log.Printf("authority ethereumAddress: %s\n", ethereumAddress)
		authorityEthAddresses = append(authorityEthAddresses, ethAddress[:])
	}

	return authorityEthAddresses, nil
}

func GetBeefyAuthoritySet(blockHash types.Hash, api *gsrpc.SubstrateAPI, method string) (types.BeefyNextAuthoritySet, error) {
	var authoritySet types.BeefyNextAuthoritySet
	// Fetch metadata
	log.Printf("blockHash: %#v\n", codec.HexEncodeToString(blockHash[:]))
	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return authoritySet, err
	}

	storageKey, err := types.CreateStorageKey(meta, "MmrLeaf", method, nil, nil)
	if err != nil {
		return authoritySet, err
	}
	log.Printf("storageKey: %#v\n", codec.HexEncodeToString(storageKey[:]))

	ok, err := api.RPC.State.GetStorage(storageKey, &authoritySet, blockHash)
	// raw, err := api.RPC.State.GetStorageRaw(storageKey, blockHash)

	if err != nil {
		log.Printf("get storage err: %#s\n", err)
		return authoritySet, err
	}

	if !ok {
		return authoritySet, fmt.Errorf("beefy authority set not found")
	}
	// log.Printf("BeefyAuthoritySet on chain : %+v\n", authoritySet)

	return authoritySet, nil

}

// convert types.SignedCommitment to beefy.SignedCommitment
func ConvertCommitment(sc types.SignedCommitment) SignedCommitment {
	var idxedSigs []Signature
	for i, v := range sc.Signatures {
		if v.IsSome() {
			_, sig := v.Unwrap()
			idxedSigs = append(idxedSigs, Signature{
				Signature: sig[:],
				Index:     uint32(i),
			})

		}
	}
	log.Printf("IndexedSignatures: %+v", idxedSigs)

	var bsc = SignedCommitment{
		Commitment: sc.Commitment,
		Signatures: idxedSigs,
	}
	log.Printf("converted commitment: %+v", bsc)
	return bsc
}

// create authority proof
func BuildAuthorityProof(authorities [][]byte, authorityIdxes []uint64) (SizedByte32, [][]byte, error) {

	var authorityLeaves [][]byte
	for _, v := range authorities {
		authorityLeaves = append(authorityLeaves, crypto.Keccak256(v))
	}
	authorityTree, err := merkle.NewTree(hasher.Keccak256Hasher{}).FromLeaves(authorityLeaves)
	if err != nil {
		return SizedByte32{}, nil, err
	}
	// var authorityTreeRoot = Bytes32(authorityTree.Root())
	authorityTreeRootRaw := authorityTree.Root()
	log.Printf("build authority merkle root raw: %#x", authorityTreeRootRaw)
	var authorityTreeRoot = Bytes32(authorityTreeRootRaw)

	log.Printf("build authority merkle root bytes32: %#x", authorityTreeRoot[:])
	authoritiesProof := authorityTree.Proof(authorityIdxes).ProofHashes()

	log.Printf("build authority proof: %+v", authoritiesProof)
	return authorityTreeRoot, authoritiesProof, nil
}

func SignatureThreshold(authorityNum uint32) uint32 {
	return 2*uint32(authorityNum)/3 + 1
}

// verify authority signatures
func VerifySignature(bsc SignedCommitment, totalLeavesCount uint64, merkleRoot SizedByte32, authorityProofs [][]byte) error {

	// beefy authorities are signing the hash of the scale-encoded Commitment
	commitmentBytes, err := codec.Encode(bsc.Commitment)
	if err != nil {
		return err
	}

	// take keccak hash of the commitment scale-encoded
	commitmentHash := crypto.Keccak256(commitmentBytes)

	// array of leaves in the authority merkle root.
	var authorityLeaves []merkletypes.Leaf

	for i := 0; i < len(bsc.Signatures); i++ {
		signature := bsc.Signatures[i]
		// recover uncompressed public key from signature
		pubkey, err := crypto.SigToPub(commitmentHash, signature.Signature)
		if err != nil {
			return err
		}

		// convert public key to ethereum address.
		address := crypto.PubkeyToAddress(*pubkey)
		authorityLeaf := merkletypes.Leaf{
			Hash:  crypto.Keccak256(address[:]),
			Index: uint64(signature.Index),
		}
		authorityLeaves = append(authorityLeaves, authorityLeaf)
	}
	authoritiesProof := merkle.NewProof(authorityLeaves, authorityProofs, totalLeavesCount, hasher.Keccak256Hasher{})
	// calMerkleRoot, err := authoritiesProof.RootHex()
	calMerkleRoot, err := authoritiesProof.Root()
	if err != nil {
		return err
	}
	log.Printf("beefy-go::VerifySignature -> cal merkle root: %#x", calMerkleRoot)
	log.Printf("beefy-go::VerifySignature -> expected merkle root: %#x", merkleRoot)

	valid, err := authoritiesProof.Verify(merkleRoot[:])
	log.Printf("beefy-go::VerifySignature -> verified result : %#v", valid)
	if err != nil || !valid {
		return err
	}

	return nil
}
