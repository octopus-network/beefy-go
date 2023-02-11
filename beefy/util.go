package beefy

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/xxhash"
)



// CreateStorageKeyPrefix creates a key prefix for keys of a map.
// Can be used as an input to the state.GetKeys() RPC, in order to list the keys of map.
func CreateStorageKeyPrefix(prefix, method string) []byte {
	return append(xxhash.New128([]byte(prefix)).Sum(nil), xxhash.New128([]byte(method)).Sum(nil)...)
}

type SizedByte32 [32]byte

func (b *SizedByte32) Marshal() ([]byte, error) {
	return b[:], nil
}

func (b *SizedByte32) Unmarshal(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	copy(b[:], data)
	return nil
}

func (b *SizedByte32) Size() int {
	return len(b)
}

type SizedByte2 [2]byte

func (b *SizedByte2) Marshal() ([]byte, error) {
	return b[:], nil
}

func (b *SizedByte2) Unmarshal(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	copy(b[:], data)
	return nil
}

func (b *SizedByte2) Size() int {
	return len(b)
}

type U8 uint8

func (u *U8) Marshal() ([]byte, error) {
	return []byte{byte(*u)}, nil
}

func (u *U8) Unmarshal(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	*u = U8(data[0])
	return nil
}

func (u *U8) Size() int {
	return 1
}

func Bytes32(bytes []byte) SizedByte32 {
	var buffer SizedByte32
	copy(buffer[:], bytes)
	return buffer
}
