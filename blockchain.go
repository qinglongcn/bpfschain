package bpfschain

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/sirupsen/logrus"
)

var (
	mutex = &sync.Mutex{} // 定义互斥锁
)

// Blockchain 表示区块链的数据结构
type Blockchain struct {
	LastHash []byte // 链上最后一个块的哈希
	// InstanceId string // 区块链的实例标识符
	// Address    string     // 区块链的钱包地址
	Database *badger.DB // 区块链数据库的句柄
}

// createBlockchain 创建一个新的区块链实例
func createBlockchain(address, instanceId, genesisCoinbaseData string, subsidy float64) (*Blockchain, error) {
	if address == "" {
		return nil, fmt.Errorf("地址不能为空")
	}
	if instanceId == "" {
		return nil, fmt.Errorf("实例ID不能为空")
	}
	path := getDatabasePath(instanceId) // 获取数据库路径
	if dbExists(path) {
		logrus.Print("区块链已经存在")
		runtime.Goexit() // 如果数据库已存在，则退出
	}

	opts := badger.DefaultOptions(path) // 设置 Badger 数据库选项
	opts.ValueDir = path
	db, err := openDB(path, opts)
	if err != nil {
		return nil, err
	}

	var lastHash []byte

	err = db.Update(func(txn *badger.Txn) error {
		cbtx := MinerTx(address, genesisCoinbaseData, subsidy) // 创建创世区块的交易
		genesis := CreateGenesisBlock(cbtx)                    // 创建创世区块

		if err := txn.Set(genesis.Hash, genesis.Serialize()); err != nil {
			return fmt.Errorf("存储创世区块失败: %w", err)
		}
		if err := txn.Set([]byte("lh"), genesis.Hash); err != nil {
			return fmt.Errorf("存储最后一个区块哈希失败: %w", err)
		}

		lastHash = genesis.Hash
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &Blockchain{
		LastHash: lastHash,
		// InstanceId: instanceId,
		// Address:    "",
		Database: db,
	}, nil
}

// ContinueBlockchain 从现有的数据库中恢复区块链实例
func ContinueBlockchain(instanceId string) (*Blockchain, error) {
	if instanceId == "" {
		return nil, fmt.Errorf("实例ID不能为空")
	}
	path := getDatabasePath(instanceId) // 获取数据库路径
	if !dbExists(path) {
		return nil, fmt.Errorf("不存在区块链数据库")
	}

	opts := badger.DefaultOptions(path) // 设置 Badger 数据库选项
	opts.ValueDir = path
	db, err := openDB(path, opts)
	if err != nil {
		return nil, err
	}

	var lastHash []byte

	err = db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("lh")) // 从数据库获取最后一个区块哈希
		if err != nil {
			return err
		}
		lastHash, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		return nil, err
	}

	return &Blockchain{
		LastHash: lastHash,
		// InstanceId: instanceId,
		// Address:    "",
		Database: db,
	}, nil
}

// AddBlock 向区块链中添加一个新区块
func (chain *Blockchain) AddBlock(block *Block) error {
	mutex.Lock() // 锁定数据库
	defer mutex.Unlock()

	return chain.Database.Update(func(txn *badger.Txn) error {
		if _, err := txn.Get(block.Hash); err == nil {
			return nil // 如果区块已存在，则不添加
		}

		item, err := txn.Get([]byte("lh")) // 获取最后一个区块的哈希
		if err == nil {
			lastHash, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			item, err = txn.Get(lastHash)
			if err != nil {
				return err
			}
			lastBlockData, _ := item.ValueCopy(nil)
			lastBlock := DeserializeBlock(lastBlockData)
			if !block.IsBlockValid(lastBlock) {
				return fmt.Errorf("无效的区块")
			}

			blockData := block.Serialize() // 序列化新区块
			if err := txn.Set(block.Hash, blockData); err != nil {
				return err // 存储新区块
			}

			if err := txn.Set([]byte("lh"), block.Hash); err != nil {
				return err // 更新最后一个区块哈希
			}
		} else {
			return err
		}

		chain.LastHash = block.Hash // 更新链上最后一个区块的哈希
		return nil
	})
}

// GetBlock 根据区块哈希获取区块
func (chain *Blockchain) GetBlock(blockHash []byte) (*Block, error) {
	block := new(Block)

	err := chain.Database.View(func(txn *badger.Txn) error {
		item, err := txn.Get(blockHash)
		if err != nil {
			if err == badger.ErrKeyNotFound { // 如果返回 ErrKeyNotFound 错误，说明区块不存在
				return fmt.Errorf("区块不存在")
			}
			return err
		}

		blockData, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		block = DeserializeBlock(blockData) // 反序列化区块数据

		return nil
	})
	if err != nil {
		return nil, err
	}

	return block, nil
}

// MineBlock 挖掘新的区块并将其添加到区块链中
func (chain *Blockchain) MineBlock(transactions []*Transaction) (*Block, error) {
	// 验证交易的合法性
	for _, tx := range transactions {
		if !chain.VerifyTransaction(tx) {
			return nil, fmt.Errorf("无效的交易: %s", tx.ID)
		}
	}

	// 从数据库中获取最后一个区块的哈希和高度
	var lastHash []byte
	var lastHeight int
	err := chain.Database.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("lh"))
		if err != nil {
			return err
		}
		lastHash, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}

		item, err = txn.Get(lastHash) // 使用区块哈希作为键来获取区块数据
		if err != nil {
			return err
		}
		lastBlockData, err := item.ValueCopy(nil) // 获取区块数据
		if err != nil {
			return err
		}
		lastBlock := DeserializeBlock(lastBlockData) // 反序列化区块数据

		lastHeight = lastBlock.Height // 获取最后一个区块的高度
		return nil
	})
	if err != nil {
		return nil, err
	}

	// 创建新区块
	block := CreateBlock(transactions, lastHash, lastHeight+1) // 区块高度+1
	// 将新区块添加到区块链中
	if err := chain.AddBlock(block); err != nil {
		return nil, err
	}

	return block, nil
}

// FindUTXO 查找所有未花费的交易输出
func (chain *Blockchain) FindUTXO() map[string]TxOutputs {
	UTXOs := make(map[string]TxOutputs) // 未花费的交易输出
	spentTXOs := make(map[string][]int) // 已花费的交易输出

	iter := chain.Iterator() // 创建一个新的区块链迭代器
	for {
		block := iter.Next() // 返回区块链中的下一个区块

		for _, tx := range block.Transactions { // 遍历区块中的交易
			txID := hex.EncodeToString(tx.ID) // 交易ID转为字符串

		Outputs:
			for outIdx, out := range tx.Vout { // 遍历交易中的输出
				if spentTXOs[txID] != nil { // 检查输出是否已被花费
					for _, spentOut := range spentTXOs[txID] {
						if spentOut == outIdx {
							continue Outputs
						}
					}
				}
				// 如果输出未被花费，则添加到UTXOs映射中
				outs := UTXOs[txID]
				outs.Outputs = append(outs.Outputs, out)
				UTXOs[txID] = outs
			}

			// 如果不是创世区块的交易，遍历交易输入，标记已花费的输出
			if !tx.IsCoinbase() {
				// 持续跟踪已花费交易输出
				for _, in := range tx.Vin {
					inTxID := hex.EncodeToString(in.ID)
					spentTXOs[inTxID] = append(spentTXOs[inTxID], in.Vout)
				}
			}
		}
		if len(block.PrevHash) == 0 {
			break
		}
	}

	// 返回未花费的交易输出映射
	return UTXOs
}

// FindTransaction 查找一个特定的交易
func (chain *Blockchain) FindTransaction(ID []byte) (*Transaction, error) {
	// 创建一个新的区块链迭代器
	iter := chain.Iterator()

	for {
		// 返回区块链中的下一个区块
		block := iter.Next()

		// 遍历区块中的交易
		for _, tx := range block.Transactions {
			// 如果找到了匹配的交易ID，将交易返回
			if bytes.Equal(tx.ID, ID) {
				return tx, nil
			}
		}

		if len(block.PrevHash) == 0 {
			break
		}
	}

	return nil, fmt.Errorf("未找到交易: %x", ID)
}

// SignTransaction 对交易的输入进行签名
func (chain *Blockchain) SignTransaction(priv *ecdsa.PrivateKey, tx *Transaction) {
	prevTxs := chain.getTransaction(tx)
	tx.Sign(priv, prevTxs)
}

// VerifyTransaction 验证交易的输入签名
func (chain *Blockchain) VerifyTransaction(tx *Transaction) bool {
	if tx.IsCoinbase() {
		return true
	}
	prevTxs := chain.getTransaction(tx)

	// 验证交易输入的签名
	return tx.Verify(prevTxs)
}

// getDatabasePath 获取数据库路径
func getDatabasePath(instanceId string) string {
	if instanceId != "" {
		return filepath.Join(BlockchainDbPath, fmt.Sprintf("blocks_%s", instanceId))
	}

	return BlockchainDbPath
}

// dbExists 检查数据库是否存在
func dbExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return false
	}
	return true
}

// openDB 打开数据库，如果因为存在 LOCK 文件打开失败，执行 retry 确保打开
func openDB(path string, opts badger.Options) (*badger.DB, error) {
	db, err := badger.Open(opts)
	if err != nil && strings.Contains(err.Error(), "LOCK") {
		db, err = retry(path, opts)
		if err != nil {
			return nil, fmt.Errorf("无法解锁数据库: %w", err)
		}
		return db, nil
	} else if err != nil {
		return nil, err
	}
	return db, nil
}

// retry 删除 lock 文件，并再次尝试打开数据库
func retry(path string, opts badger.Options) (*badger.DB, error) {
	lockPath := filepath.Join(path, "LOCK")

	// 检查锁文件是否可以安全删除
	if err := checkLock(lockPath); err != nil {
		return nil, err
	}

	if err := os.Remove(lockPath); err != nil {
		return nil, fmt.Errorf("移除 LOCK: %w", err)
	}

	// 使用退避算法重试打开数据库
	var db *badger.DB
	var err error
	for i := 0; i < 3; i++ {
		db, err = badger.Open(opts)
		if err == nil {
			return db, nil
		}
		logrus.Errorf("打开数据库失败，%d 秒后重试", i+1)
		time.Sleep(time.Duration(i+1) * time.Second)
	}

	return nil, fmt.Errorf("打开数据库失败: %w", err)
}

// checkLock 检查锁文件是否可以安全删除
func checkLock(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("打开 LOCK 文件失败: %w", err)
	}
	defer file.Close()

	// 尝试获取文件锁
	err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		return fmt.Errorf("数据库正被其他进程使用: %w", err)
	}

	// 释放文件锁
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)

	return nil
}

// getTransaction 获取交易的map格式
func (chain *Blockchain) getTransaction(transaction *Transaction) map[string]Transaction {
	txs := make(map[string]Transaction)
	for _, in := range transaction.Vin {
		// 获取所有带有 in.ID 的交易
		tx, err := chain.FindTransaction(in.ID)
		if err != nil {
			logrus.Panic(err)
		}
		txs[hex.EncodeToString(tx.ID)] = *tx
	}

	return txs
}

// Exists 根据实例ID检查对应的数据库是否存在
func Exists(instanceId string) bool {
	path := getDatabasePath(instanceId)
	return dbExists(path)
}

// GetBlockHashes 总计得到区块链中的所有区块哈希数组
func (chain *Blockchain) GetBlockHashes(height int) [][]byte {
	var blocks [][]byte // []byte为单个block的哈希值

	iter := chain.Iterator()
	if iter == nil {
		return blocks
	}

	for {
		block := iter.Next()
		prevHash := block.PrevHash
		if block.Height == height {
			break
		}
		blocks = append([][]byte{block.Hash}, blocks...) // [][]byte{block.Hash}为只有一个元素的切片，append要求两个连接的切片类型必须相同

		if prevHash == nil {
			break
		}
	}

	return blocks
}

// GetBestHeight 得到最佳height基本上是获取最后区块的height（index）
func (chain *Blockchain) GetBestHeight() int {
	lastBlock := new(Block)

	if err := chain.Database.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("lh"))
		if err == nil {
			lastHash, _ := item.ValueCopy(nil)

			item, err = txn.Get(lastHash)
			if err != nil {
				logrus.Panic(err)
			}

			lastBlockData, _ := item.ValueCopy(nil)
			lastBlock = DeserializeBlock(lastBlockData)
		}

		return err
	}); err == nil {
		return lastBlock.Height
	}

	return 0
}
