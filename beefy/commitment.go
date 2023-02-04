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


type SignatureWithIdx struct {
	// actual signature bytes
	Signature []byte
	// authority leaf index in the merkle tree.
	AuthorityIndex uint32
}
type ConvertedSignedCommitment struct {
	Commitment types.Commitment
	Signatures []SignatureWithIdx
}


