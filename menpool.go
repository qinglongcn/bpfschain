package bpfschain

import (
	"encoding/hex"
	"sync"

	"go.uber.org/fx"
)

// MemoryPool 区块链交易内存池数据结构
type MemoryPool struct {
	Pending         map[string]Transaction // 挂起的交易队列
	Queued          map[string]Transaction // 排队的交易队列
	BlocksInTransit [][]byte               // 待交换中所有block的哈希（通过发送inv，获取的block可能有多个，可以先缓存于此）
	Blocks          chan *Block            // Block类型的通道（带缓冲的通道：在StartNode函数中构建Network实例，缓冲数量200）
	Transactions    chan *Transaction      // Transaction类型的通道（带缓冲的通道：在StartNode函数中构建Network实例，缓冲数量200）
	BlockPubsub     map[int]*Block         // 暂存区块，解决网络超前获取的块

	Wg sync.WaitGroup
}

type NewMemoryPoolOutput struct {
	fx.Out
	Pool *MemoryPool // 文件上传内存池
}

// NewMemoryPool 初始化一个新的文件上传内存池
func NewMemoryPool(lc fx.Lifecycle) (out NewMemoryPoolOutput, err error) {
	out.Pool = &MemoryPool{ // 区块链交易内存池
		Pending:         map[string]Transaction{}, // 挂起的交易队列
		Queued:          map[string]Transaction{}, // 排队的交易队列
		BlocksInTransit: [][]byte{},

		Blocks:       make(chan *Block, 200),       // 新Block数量不超过200个
		Transactions: make(chan *Transaction, 200), // 新Tansaction数量不超过200个

		BlockPubsub: map[int]*Block{}, // 暂存区块

		// WaitGroup 等待一组 goroutine 完成。 主 goroutine 调用 Add 来设置要等待的 goroutines 的数量。 然后每个 goroutines 运行并在完成时调用 Done。 同时，Wait 可以用来阻塞，直到所有的 goroutines 完成。
		// 第一次使用后不得复制 WaitGroup。
		Wg: sync.WaitGroup{}, // 等待组
	}

	return out, nil
}

// Move 将交易从一个队列中移到另外一个队列
func (memo *MemoryPool) Move(tnx *Transaction, to string) {
	if to == "pending" {
		memo.Remove(hex.EncodeToString(tnx.ID), "queued")
		memo.Pending[hex.EncodeToString(tnx.ID)] = *tnx
	}

	if to == "queued" {
		memo.Remove(hex.EncodeToString(tnx.ID), "pending")
		memo.Queued[hex.EncodeToString(tnx.ID)] = *tnx
	}
}

// Add 添加新的交易到交易内存池
func (memo *MemoryPool) Add(tnx *Transaction) {
	memo.Pending[hex.EncodeToString(tnx.ID)] = *tnx
}

// Remove从某个队列中删除交易
func (memo *MemoryPool) Remove(txID string, from string) {
	if from == "queued" {
		delete(memo.Queued, txID)
		return
	}

	if from == "pending" {
		delete(memo.Pending, txID)
		return
	}
}

// GetTransactions 从挂起交易队列中得到指定数量的交易
func (memo *MemoryPool) GetTransactions(count int) (txs [][]byte) {
	i := 0
	for _, tx := range memo.Pending {
		txs = append(txs, tx.ID)
		if i == count {
			break
		}
		i++
	}
	return txs
}

// RemoveFromAll 从挂起和排队队列中全部删除某个交易
func (memo *MemoryPool) RemoveFromAll(txID string) {
	delete(memo.Queued, txID)
	delete(memo.Pending, txID)
}

// ClearAll 从内存池中清除全部的交易
func (memo *MemoryPool) ClearAll() {
	memo.Pending = map[string]Transaction{}
	memo.Queued = map[string]Transaction{}
}
