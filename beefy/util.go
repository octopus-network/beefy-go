package beefy

// local testnet
const LOCAL_RELAY_ENDPPOIT = "ws://127.0.0.1:9944"
const LOCAL_PARACHAIN_ENDPOINT = "ws://127.0.0.1:9988"
const LOCAL_PARACHAIN_ID uint32 = 2222

// Rococo testnet
const ROCOCO_ENDPOIN = "wss://rococo-rpc.polkadot.io"

// Rockmine
const ROCOCO_ROCKMIN_ID uint32 = 1000
const ROCOCO_ROCKMIN_ENDPOINT = "wss://rococo-rockmine-rpc.polkadot.io"

// Polkadot mainnet
const POLKADOT_ENDPOINT = "wss://rpc.polkadot.io"

// Astar
const POLKADOT_ASTAR_ID uint32 = 2006
const POLKADOT_ASTAR_ENDPOINT = "wss://rpc.astar.network"

// Composable Finance
const POLKADOT_COMPOSABLE_ID uint32 = 2019
const POLKADOT_COMPOSABLE_ENDPOINT = "wss://rpc.composable.finance"

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

// beefy activation block height
const BEEFY_ACTIVATION_BLOCK uint32 = 0

// from mmr leaf index to blocknumber
func ConvertMmrLeafIndexToBlockNumber(beefyActivationBlock uint32, leafIndex uint32) uint32 {
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

// ConvertBlockNumberToMmrLeafIndex given the MmrLeafPartial.ParentNumber & BeefyActivationBlock,
func ConvertBlockNumberToMmrLeafIndex(beefyActivationBlock uint32, blockNumber uint32) uint64 {
	var leafIndex uint32

	// calculate the leafIndex for this leaf.
	if beefyActivationBlock == 0 {
		// in this case the leaf index is the same as the block number - 1 (leaf index starts at 0)
		leafIndex = blockNumber - 1
	} else {
		// in this case the leaf index is activation block - current block number.
		// leafIndex = beefyActivationBlock - (blockNumber + 1)
		leafIndex = (blockNumber + 1) - beefyActivationBlock
	}

	return uint64(leafIndex)
}
