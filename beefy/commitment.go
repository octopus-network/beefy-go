package beefy

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/scale"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

type VersionedFinalityProof struct {
	Version          uint8
	SignedCommitment types.SignedCommitment
}

func (vfp *VersionedFinalityProof) Decode(decoder scale.Decoder) error {
	b, err := decoder.ReadOneByte()
	if err != nil {
		return err
	}

	switch b {
	case 1:
		vfp.Version = 1
		err = decoder.Decode(&vfp.SignedCommitment)

	}

	if err != nil {
		return err
	}

	return nil
}

func (vfp VersionedFinalityProof) Encode(encoder scale.Encoder) error {
	var err1, err2 error

	// if v.V1.(types.SignedCommitment) {
	// 	err1 = encoder.PushByte(1)
	// 	err2 = encoder.Encode(v.V1)
	// }
	switch vfp.Version {
	case 1:
		err1 = encoder.PushByte(1)
		err2 = encoder.Encode(vfp.SignedCommitment)

	}

	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}

	return nil
}

// type SignatureWithIdx struct {
// 	// actual signature bytes
// 	Signature []byte
// 	// authority leaf index in the merkle tree.
// 	AuthorityIndex uint32
// }
// Signature with it`s index in merkle tree
// type IndexedSignature struct {
// 	// signature leaf index in the merkle tree.
// 	Index uint32 `json:"index,omitempty"`
// 	// signature bytes
// 	Signature []byte `json:"signature,omitempty"`
// }

// type ConvertedSignedCommitment struct {
// 	Commitment types.Commitment
// 	Signatures []IndexedSignature
// }

// signed commitment data
type SignedCommitment struct {
	// commitment data being signed
	Commitment types.Commitment `json:"commitment,omitempty"`
	// all the signatures
	Signatures []Signature `json:"indexed_signatures,omitempty"`
}

// // Actual payload items
// type PayloadItem struct {
// 	// 2-byte payload id
// 	Id [2]byte `json:"payload_id,omitempty"`
// 	// arbitrary length payload data., eg mmr_root_hash
// 	Data []byte `json:"payload_data,omitempty"`
// }

// type Commitment struct {
// 	// array of payload items signed by Beefy validators
// 	Payload []PayloadItem `json:"payload,omitempty"`
// 	// block number for this commitment
// 	BlockNumber uint32 `json:"block_number,omitempty"`
// 	// validator set that signed this commitment
// 	ValidatorSetId uint64 `json:"validator_set_id,omitempty"`
// }
