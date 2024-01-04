package bpfschain

import (
	"bytes"
	"crypto/sha256"
	"math"
	"math/big"
)

// 区块的工作量证明难度
const Difficulty = 5

var (
	maxNonce = math.MaxInt64
)

// ProofOfWork 表示工作量证明
type ProofOfWork struct {
	Block  *Block   // 需要进行工作量证明的区块
	Target *big.Int // 目标哈希值，用于与计算出的哈希值进行比较
}

// NewProofOfWork 创建一个新的工作量证明实例
func NewProof(b *Block) *ProofOfWork {
	// 创建一个 big.Int 的实例，并将其值设置为 1
	target := big.NewInt(1)

	// 将 target 左移 (256 - b.Difficulty) 位，得到目标哈希值
	// 256 是 SHA-256 哈希算法的位数，b.Difficulty 是区块的难度系数
	// 难度系数越大，目标哈希值越小，挖矿难度越大
	target.Lsh(target, uint(256-b.Difficulty))

	// 创建一个新的 ProofOfWork 实例
	// 其中 block 是需要进行工作量证明的区块，target 是目标哈希值
	pow := &ProofOfWork{
		Block:  b,      // 需要进行工作量证明的区块
		Target: target, // 目标哈希值，用于与计算出的哈希值进行比较
	}

	return pow
}

// Run进行工作量证明算法，找到符合条件的随机数和哈希值
func (pow *ProofOfWork) Run() (int, []byte) {
	// 初始化一个大整数变量，用于存储计算出的哈希值
	var hashInt big.Int
	var hash [32]byte

	// 初始化一个无符号 64 位整数变量，用于存储 nonce
	var nonce int

	for nonce < maxNonce {
		// 准备数据
		data := pow.prepareData(nonce)
		// 计算哈希值
		hash = sha256.Sum256(data)
		// 将哈希值转换为大整数
		hashInt.SetBytes(hash[:])

		// 比较哈希值和目标值
		if hashInt.Cmp(pow.Target) == -1 {
			break
		} else {
			nonce++
		}
	}

	// 返回满足条件的 nonce 和哈希值
	return nonce, hash[:]
}

// Validate 验证区块的合法性
// 返回值表示区块的工作量证明是否有效
func (pow *ProofOfWork) Validate() bool {
	var initHash big.Int
	var hash [32]byte

	info := pow.prepareData(pow.Block.Nonce)
	hash = sha256.Sum256(info)

	initHash.SetBytes(hash[:])

	return initHash.Cmp(pow.Target) == -1
}

// prepareData 准备数据，用于计算哈希值
// func (pow *ProofOfWork) prepareData(nonce int) []byte {
// 	// 使用 bytes 包中的 Buffer 结构体，用于存储拼接后的字节数据
// 	info := bytes.Join(
// 		[][]byte{
// 			pow.Block.HashTransactions(),
// 			pow.Block.PrevHash,
// 			ToByte(int64(nonce)),
// 			ToByte(int64(Difficulty)),
// 		}, []byte{})

//		return info
//	}
func (pow *ProofOfWork) prepareData(nonce int) []byte {
	var buff bytes.Buffer

	buff.Write(pow.Block.HashTransactions())
	buff.Write(pow.Block.PrevHash)
	buff.Write(ToBytes[int](nonce))
	buff.Write(ToBytes[int](Difficulty))

	return buff.Bytes()
}
