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

// signed commitment data
type SignedCommitment struct {
	// commitment data being signed
	Commitment types.Commitment `json:"commitment,omitempty"`
	// all the signatures
	Signatures []Signature `json:"indexed_signatures,omitempty"`
}

