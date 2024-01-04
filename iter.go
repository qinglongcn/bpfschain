package bpfschain

import (
	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
)

// BlockchainIterator 区块链迭代器
type BlockchainIterator struct {
	CurrentHash []byte
	Database    *badger.DB
}

// Iterator 创建一个新的区块链迭代器
func (chain *Blockchain) Iterator() *BlockchainIterator {
	if chain.LastHash == nil {
		return nil
	}

	return &BlockchainIterator{chain.LastHash, chain.Database}
}

// Next 返回区块链中的下一个区块
func (iter *BlockchainIterator) Next() *Block {
	block := new(Block)

	// 使用 View 方法来读取数据库，因为我们只需要获取数据，不需要写入
	err := iter.Database.View(func(txn *badger.Txn) error {
		// 使用当前哈希作为键来获取区块数据
		item, err := txn.Get(iter.CurrentHash)
		if err != nil {
			return err
		}

		// 获取区块数据
		blockData, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}

		// 反序列化区块数据
		block = DeserializeBlock(blockData)

		return nil
	})

	if err != nil {
		logrus.Printf("获取区块时出错: %v", err)
		return nil
	}

	// 更新迭代器中的当前哈希为前一个区块的哈希
	iter.CurrentHash = block.PrevHash

	// 返回获取到的区块
	return block
}
