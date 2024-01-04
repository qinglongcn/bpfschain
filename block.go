package bpfschain

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
)

// Block 表示区块链中的一个区块
type Block struct {
	Timestamp    int64          `json:"timestamp"`    // 区块创建的时间戳
	Hash         []byte         `json:"hash"`         // 当前区块的哈希值
	PrevHash     []byte         `json:"prevHash"`     // 前一个区块的哈希值
	Transactions []*Transaction `json:"transactions"` // 区块中包含的交易列表
	Nonce        int            `json:"nonce"`        // 工作量证明算法中的随机数
	Height       int            `json:"height"`       // 区块在区块链中的位置高度
	MerkleRoot   []byte         `json:"merkleRoot"`   // 交易的Merkle树根哈希值
	Difficulty   int            `json:"difficulty"`   // 区块的工作量证明难度
	TxCount      int            `json:"txCount"`      // 区块中的交易数量
}

// CreateBlock 创建并返回一个新的区块
func CreateBlock(txs []*Transaction, prevHash []byte, height int) *Block {
	block := &Block{
		Timestamp:    time.Now().Unix(), // 区块创建的时间戳
		Hash:         []byte{},          // 当前区块的哈希值
		PrevHash:     prevHash,          // 前一个区块的哈希值
		Transactions: txs,               // 区块中包含的交易列表
		Nonce:        0,                 // 工作量证明算法中的随机数
		Height:       height,            // 区块在区块链中的位置高度
		MerkleRoot:   []byte{},          // 交易的Merkle树根哈希值
		Difficulty:   Difficulty,        // 区块的工作量证明难度
		TxCount:      len(txs),          // 区块中的交易数量
	}

	// 计算并设置 Merkle 树的根节点
	block.MerkleRoot = block.HashTransactions()

	// 创建一个新的工作量证明实例
	pow := NewProof(block)
	// 进行工作量证明算法，找到符合条件的随机数和哈希值
	nonce, hash := pow.Run()

	// 设置新区块的哈希和随机值
	block.Hash = hash[:]
	block.Nonce = nonce

	return block
}

// CreateGenesisBlock 创建并返回创世区块
func CreateGenesisBlock(coinbase *Transaction) *Block {
	//  创建一个新的区块
	return CreateBlock([]*Transaction{coinbase}, []byte{}, 1)
}

// HashTransactions 生成并返回交易的Merkle树根哈希值
func (b *Block) HashTransactions() []byte {
	var transactions [][]byte

	for _, tx := range b.Transactions {
		transactions = append(transactions, tx.Serialize())
	}

	mTree := NewMerkleTree(transactions)

	return mTree.RootNode.Data
}

// IsGenesis 判断当前区块是否为创世区块
func (b *Block) IsGenesis() bool {
	// 前一个区块的哈希值
	return b.PrevHash == nil
}

// IsBlockValid 验证区块的完整性和有效性
func (b *Block) IsBlockValid(lastBlock *Block) bool {
	// TODO: 添加验证逻辑，例如验证区块的哈希、交易等
	// 1. 验证区块的哈希是否正确
	// 2. 验证区块的工作量证明
	// 3. 验证区块中的每个交易
	// 4. 验证区块的 Merkle 树根哈希值
	// 5. 验证区块的高度和前一个区块的高度关系
	if lastBlock.Height+1 != b.Height {
		logrus.Printf("Expected Height: %d, Actual Height: %d\n", lastBlock.Height+1, b.Height)
		return false
	}
	// 是否具有相同的长度并包含相同的字节
	if !bytes.Equal(lastBlock.Hash, b.PrevHash) {
		logrus.Printf("Expected PrevHash: %x, Actual PrevHash: %x\n", lastBlock.Hash, b.PrevHash)
		return false
	}

	return true
}

// Serialize 将区块序列化为字节切片
func (b *Block) Serialize() []byte {
	var buff bytes.Buffer

	encoder := gob.NewEncoder(&buff)
	if err := encoder.Encode(b); err != nil {
		logrus.Panic(err)
	}

	return buff.Bytes()
}

// DeserializeBlock 将字节切片反序列化为区块
func DeserializeBlock(data []byte) *Block {
	block := new(Block)

	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(block); err != nil {
		logrus.Panic(err)
	}

	return block
}

// MarshalJSON 将区块转换为JSON格式的字节切片
func (b *Block) MarshalJSON() ([]byte, error) {
	var buffer bytes.Buffer
	buffer.WriteString("{")
	buffer.WriteString(fmt.Sprintf("\"Timestamp\":%d,", b.Timestamp))       // 区块创建的时间戳
	buffer.WriteString(fmt.Sprintf("\"Hash\":\"%x\",", b.Hash))             // 当前区块的哈希值
	buffer.WriteString(fmt.Sprintf("\"PrevHash\":\"%x\",", b.PrevHash))     // 前一个区块的哈希值
	buffer.WriteString(fmt.Sprintf("\"Nonce\":%d,", b.Nonce))               // 工作量证明算法中的随机数
	buffer.WriteString(fmt.Sprintf("\"Height\":%d,", b.Height))             // 区块在区块链中的位置高度
	buffer.WriteString(fmt.Sprintf("\"MerkleRoot\":\"%x\",", b.MerkleRoot)) // 交易的Merkle树根哈希值
	buffer.WriteString(fmt.Sprintf("\"Difficulty\":%d,", b.Difficulty))     // 区块的工作量证明难度
	buffer.WriteString(fmt.Sprintf("\"TxCount\":%d", b.TxCount))            // 区块中的交易数量
	buffer.WriteString("}")
	return buffer.Bytes(), nil
}
