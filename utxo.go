package bpfschain

import (
	"bytes"
	"encoding/hex"

	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
)

var (
	utxoPrefix = []byte("utxo-") // 键值前缀
)

// UTXOSet 代表UTXO集，通常是一个区块链中所有未花费的交易输出（UTXO）集合
type UTXOSet struct {
	Chain *Blockchain
}

// FindSpendableOutputs 查找并返回要在输入中引用的未使用的输出
func (u *UTXOSet) FindSpendableOutputs(pubKeyHash []byte, amount float64) (float64, map[string][]int) {
	unspentOuts := make(map[string][]int)
	accumulated := float64(0)

	db := u.Chain.Database

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		// 要启用仅可以用键迭代，需要将 IteratorOptions.PrefetchValues 字段设置为 false
		opts.PrefetchValues = false
		// 使用 badger 提供的前缀查找功能来查找所有 UTXO
		it := txn.NewIterator(opts)
		defer it.Close()

		// 使用前缀来查找所有相关的 UTXO
		for it.Seek(utxoPrefix); it.ValidForPrefix(utxoPrefix); it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)

			v, err := item.ValueCopy(nil)
			if err != nil {
				logrus.Panic(err)
			}
			outs := DeSerializeOutputs(v)

			k = bytes.TrimPrefix(k, utxoPrefix)
			// 从 key 中解析出交易 ID
			txID := hex.EncodeToString(k)

			// 遍历 UTXO 的所有输出
			for outIdx, out := range outs.Outputs {
				// 如果 UTXO 输出是使用给定的公钥哈希锁定的，并且可花费的 UTXO 的总价值小于所需花费的金额，则将该 UTXO 添加到可花费的 UTXO 列表中
				if out.IsLockWithKey(pubKeyHash) && accumulated < amount {
					// 交易输出的值为0，或者资产的唯一标识符不为nil，属于资产交易
					if out.Value == 0 || out.AssetID != nil {
						continue // 跳过
					}

					accumulated += out.Value
					unspentOuts[txID] = append(unspentOuts[txID], outIdx)
					if accumulated >= amount { // 足够交易，停止继续取出
						break
					}
				}
			}
		}

		return nil
	})
	if err != nil {
		logrus.Panic(err)
	}

	// 返回找到的可花费的 UTXO 的总价值和可花费的 UTXO 列表
	return accumulated, unspentOuts
}

// FindUnSpentTransactions 根据公钥哈希，得到所有UTXO(给出地址余额)
func (u UTXOSet) FindUnSpentTransactions(pubKeyHash []byte) []TxOutput {
	var UTXOs []TxOutput
	db := u.Chain.Database

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		// 使用 badger 提供的前缀查找功能来查找所有 UTXO
		it := txn.NewIterator(opts)
		defer it.Close()

		// 使用前缀来查找所有相关的 UTXO
		for it.Seek(utxoPrefix); it.ValidForPrefix(utxoPrefix); it.Next() {
			item := it.Item()
			v, err := item.ValueCopy(nil)
			if err != nil {
				logrus.Panic(err)
			}

			// 反序列化 UTXO 的输出
			outs := DeSerializeOutputs(v)

			// 遍历 UTXO 的输出
			for _, out := range outs.Outputs {
				// 如果 UTXO 输出是使用给定的公钥哈希锁定的，并且交易输出的值不为0，则将该 UTXO 添加到 UTXOs 列表中
				if out.IsLockWithKey(pubKeyHash) {
					// 交易输出的值为0，或者资产的唯一标识符不为nil，属于资产交易
					if out.Value == 0 || out.AssetID != nil {
						continue // 跳过
					}

					UTXOs = append(UTXOs, out)
				}
			}
		}

		return nil
	})
	if err != nil {
		logrus.Panic(err)
	}

	// 返回找到的 UTXOs 列表
	return UTXOs
}

// IsAssetSpendable 检查特定资产是否未被消费
func (u *UTXOSet) IsAssetSpendable(pubKeyHash, assetID []byte) (bool, string, int) {
	var isSpendable = false
	var txID string
	var idx int

	db := u.Chain.Database

	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		// 要启用仅可以用键迭代，需要将 IteratorOptions.PrefetchValues 字段设置为 false
		opts.PrefetchValues = false
		// 使用 badger 提供的前缀查找功能来查找所有 UTXO
		it := txn.NewIterator(opts)
		defer it.Close()

		// 使用前缀来查找所有相关的 UTXO
		for it.Seek(utxoPrefix); it.ValidForPrefix(utxoPrefix); it.Next() {
			item := it.Item()
			k := item.KeyCopy(nil)

			v, err := item.ValueCopy(nil)
			if err != nil {
				logrus.Panic(err)
			}
			outs := DeSerializeOutputs(v)

			k = bytes.TrimPrefix(k, utxoPrefix)
			// 从 key 中解析出交易 ID
			txID = hex.EncodeToString(k)

			// 遍历 UTXO 的所有输出
			for outIdx, out := range outs.Outputs {
				// 如果 UTXO 输出是使用给定的公钥哈希锁定的，并且资产 ID 匹配，则标记资产为可花费
				if out.IsLockWithKey(pubKeyHash) && bytes.Equal(out.AssetID, assetID) {
					// 交易输出的值不为0，不属于纯粹的资产交易
					if out.Value != 0 {
						continue // 跳过
					}

					isSpendable = true
					idx = outIdx
					return nil // 找到匹配的资产，提前退出循环
				}
			}
		}

		return nil
	})
	if err != nil {
		logrus.Panic(err)
	}

	// 返回资产是否可花费和未消费的资产的 UTXO 的交易 ID 和输出索引
	return isSpendable, txID, idx
}

// CountTransactions 返回UTXO集中的交易数量
func (u *UTXOSet) CountTransactions() int {
	var counter int

	db := u.Chain.Database
	err := db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		// 使用 badger 提供的前缀查找功能来查找所有 UTXO
		it := txn.NewIterator(opts)
		defer it.Close()

		// 使用前缀来查找所有相关的 UTXO
		for it.Seek(utxoPrefix); it.ValidForPrefix(utxoPrefix); it.Next() {
			// 每找到一个与前缀匹配的键，计数器加一
			counter++
		}
		return nil
	})
	if err != nil {
		logrus.Panic(err)
	}

	// 返回计数器的值，即 UTXO 的总数
	return counter
}

// Update 使用来自Block的交易更新UTXO集
// 区块被认为是区块链的顶端
func (u *UTXOSet) Update(block *Block) {
	// 获取数据库实例
	db := u.Chain.Database

	// 使用 Update 操作来更新数据
	err := db.Update(func(txn *badger.Txn) error {
		// 遍历区块中的每个交易
		for _, tx := range block.Transactions {
			// 检查交易是否是创始区块交易，如果不是，则处理输入
			// 创始区块交易不含实质的输入，也就不对该交易的输入进行处理
			if !tx.IsCoinbase() {
				for _, in := range tx.Vin {
					// 创建一个新的 TxOutputs 结构体来存储更新后的输出
					updatedOutputs := TxOutputs{}
					inID := append(utxoPrefix, in.ID...)
					// 从数据库中获取输入引用的交易 ID 所对应的输出
					item, err := txn.Get(inID)
					if err != nil {
						logrus.Panic(err)
					}
					// 获取输出的字节数据
					v, err := item.ValueCopy(nil)
					if err != nil {
						logrus.Panic(err)
					}
					// 反序列化输出数据
					outs := DeSerializeOutputs(v)

					// 遍历输出，将未被花费的输出添加到 updatedOutputs 中
					for outIdx, out := range outs.Outputs {
						// 如果UTXO中的输出不包含在当前交易中，保留到更新的UTXO集中
						if outIdx != in.Vout {
							updatedOutputs.Outputs = append(updatedOutputs.Outputs, out)
						}
					}

					// 如果更新的 updatedOutputs 为空，则从数据库中删除该交易 ID 的输出
					if len(updatedOutputs.Outputs) == 0 {
						if err := txn.Delete(inID); err != nil {
							logrus.Panic(err)
						}
					} else {
						// 否则，将更新后的输出序列化并存回数据库
						if err := txn.Set(inID, updatedOutputs.Serialize()); err != nil {
							logrus.Panic(err)
						}
					}
				}

				// 创建一个新的 TxOutputs 结构体来存储新的输出
				newOutputs := TxOutputs{}
				// 将交易中的所有输出添加到 newOutputs 中
				newOutputs.Outputs = append(newOutputs.Outputs, tx.Vout...)

				txID := append(utxoPrefix, tx.ID...)
				// 将新的输出序列化并存入数据库
				err := txn.Set(txID, newOutputs.Serialize())
				if err != nil {
					logrus.Panic(err)
				}

			} else { // 创始区块
				// 为矿工（受益者）挖矿交易更新UXTO
				newOutputs := TxOutputs{}
				newOutputs.Outputs = append(newOutputs.Outputs, tx.Vout...)
				txID := append(utxoPrefix, tx.ID...)
				err := txn.Set(txID, newOutputs.Serialize())
				if err != nil {
					logrus.Panic(err)
				}
			}
		}
		return nil
	})

	if err != nil {
		logrus.Panic(err)
	}
}

// Reindex 重建UTXO集
func (u *UTXOSet) Compute() {
	db := u.Chain.Database

	// 获取所有未花费的交易输出
	u.DeleteByPrefix(utxoPrefix)

	UTXO := u.Chain.FindUTXO()

	// 使用 WriteBatch 来批量写入数据，提高性能
	wb := db.NewWriteBatch()
	defer wb.Cancel()

	for txId, outs := range UTXO {
		// 获取所有未花费的交易输出
		key, err := hex.DecodeString(txId)
		if err != nil {
			logrus.Panic(err)
		}

		key = append(utxoPrefix, key...)
		// 遍历所有未花费的交易输出
		if err = wb.Set(key, outs.Serialize()); err != nil {
			logrus.Panic(err)
		}
	}
	// 执行批量写入操作
	if err := wb.Flush(); err != nil {
		logrus.Panic(err)
	}
}

// DeleteByPrefix 删除 UTXO 集合中的所有记录
func (u *UTXOSet) DeleteByPrefix(prefix []byte) {
	// 定义一个批量删除记录的函数
	deleteKeys := func(keysForDelete [][]byte) error {
		// 使用事务批量删除记录
		if err := u.Chain.Database.Update(func(txn *badger.Txn) error {
			for _, key := range keysForDelete {
				// 删除记录
				if err := txn.Delete(key); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		return nil
	}

	// 这是 badgerDB 一次可以删除的最大记录数,
	// 因此我们必须汇总所有带有utxo前缀的键值的记录并批量删除
	collectSize := 100000
	// 使用只读事务获取 UTXO 集合
	u.Chain.Database.View(func(txn *badger.Txn) error {
		// 创建迭代器
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		// 初始化 keysForDelete 切片
		keysForDelete := make([][]byte, 0, collectSize)
		keysCollected := 0

		// 遍历迭代器中的所有记录
		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			// 获取当前记录的键
			key := it.Item().KeyCopy(nil)

			// 将键添加到 keysForDelete 切片中
			keysForDelete = append(keysForDelete, key)
			keysCollected++

			// 如果 keysForDelete 切片中的记录数达到指定的集合大小，则批量删除这些记录
			if keysCollected == collectSize {
				if err := deleteKeys(keysForDelete); err != nil {
					logrus.Panic(err)
				}
				// 复位 keys，继续删除指定集合大小的记录
				keysForDelete = make([][]byte, 0, collectSize)
				keysCollected = 0
			}
		}

		// 如果 keysForDelete 切片中还有记录，则批量删除这些记录
		if keysCollected > 0 {
			if err := deleteKeys(keysForDelete); err != nil {
				logrus.Panic(err)
			}
		}

		return nil
	})
}
