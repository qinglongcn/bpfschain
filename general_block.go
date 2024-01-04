package bpfschain

import (
	"context"
	"encoding/hex"

	"github.com/bpfs/dep2p"
	"github.com/bpfs/dep2p/pubsub"
	"github.com/bpfs/dep2p/streams"
	"github.com/btcsuite/btcd/txscript"
	"github.com/sirupsen/logrus"
)

// SendBlock 向指定的 peer 发送一个区块
func SendBlock(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, block *Block, peerId string) error {
	// 编码
	payloadBytes, err := EncodeToBytes(block)
	if err != nil {
		logrus.Errorf("[SendBlock] 编码失败:\t%v", err)
		return err
	}

	// 请求消息
	srm := &streams.RequestMessage{
		Payload: payloadBytes,
		Message: &streams.Message{
			Sender:   p2p.Host().ID().String(), // 发送方ID
			Receiver: peerId,                   // 接收方ID
		},
	}

	// 序列化
	requestBytes, err := srm.Marshal()
	if err != nil {
		logrus.Errorf("[SendBlock] 序列化失败:\t%v", err)
		return err
	}

	// 发送区块数据
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainGeneralBlockChannel, requestBytes); err != nil {
		logrus.Errorf("[SendBlock] 发送失败:\t%v", err)
		return err
	}

	return nil
}

// HandleBlock 处理接收到的区块数据
func HandleBlock(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, db *SqliteDB, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	block := new(Block)
	if err := DecodeFromBytes(request.Payload, block); err != nil {
		logrus.Errorf("[HandleBlock] 解码失败:\t%v", err)
		return
	}

	// 判断区块是否是创世区块
	if block.IsGenesis() {
		chain.AddBlock(block)
	} else {
		// 获取最后一个区块
		lastBlock, err := chain.GetBlock(chain.LastHash)
		if err != nil {
			logrus.Errorf("[HandleBlock] 获取最后一个区块失败:\t%v", err)
			return
		}

		// 网络获取的区块高度，大于当前所需的区块高度
		if block.Height > lastBlock.Height+1 {
			// 将区块暂存
			pool.BlockPubsub[block.Height] = block
			return
		} else if block.Height < lastBlock.Height+1 {
			return
		}

		// 验证获取区块的完整性和有效性
		valid := block.IsBlockValid(lastBlock)
		if valid {
			// 处理并添加区块到区块链，同时从内存池中移除交易
			processBlock(db, chain, pool, block, opt.Pub)

			// 循环处理暂存中的连续区块
			for {
				nextHeight := lastBlock.Height + 1
				if nextBlock, ok := pool.BlockPubsub[nextHeight]; ok {
					// 处理并添加区块到区块链，同时从内存池中移除交易
					processBlock(db, chain, pool, nextBlock, opt.Pub)
					delete(pool.BlockPubsub, nextHeight) // 处理完后从暂存中移除
				} else {
					break // 没有更多连续的区块
				}
			}

		} else {
			logrus.Fatalf("发现一个非法区块，其 height 是: %d", block.Height)

			// 出现非法区块是非常严重的业务逻辑错误，程序需要终止执行
			// 同步调用CloseDB进行阻塞，等待程序强行终止信号，退出程序（不会继续执行本行代码之后的代码）
			//
			// 关闭区块链数据库
			CloseDB(chain)
		}
	}

	if len(block.Transactions) > 0 {
		for _, tx := range block.Transactions {
			pool.RemoveFromAll(hex.EncodeToString(tx.ID))
		}
	}

	if len(pool.BlocksInTransit) > 0 {
		// 取出第一个待交换的block的hash
		blockHash := pool.BlocksInTransit[0]

		// 向指定的 peer 发送获取区块数据的请求
		if err := SendGetDataBlock(p2p, pubsub, request.Message.Sender, blockHash, opt.IsMinerNode); err != nil {
			logrus.Errorf("[HandleBlock] 向指定的 peer 发送获取区块数据的请求失败:\t%v", err)
		}

		// 将此block的hash从待交换block hashes列表中移除
		pool.BlocksInTransit = pool.BlocksInTransit[1:]
	} else {
		UTXO := UTXOSet{Chain: chain}
		// 使用来自Block的交易更新UTXO集
		UTXO.Compute()
	}

}

// processBlock 处理并添加区块到区块链，同时从内存池中移除交易
func processBlock(db *SqliteDB, chain *Blockchain, pool *MemoryPool, block *Block, publicKey []byte) {
	// 向区块链中添加一个新区块
	if err := chain.AddBlock(block); err != nil {
		return
	}

	// 从内存池中移除交易
	for _, tx := range block.Transactions {
		txID := hex.EncodeToString(tx.ID)
		pool.RemoveFromAll(txID)
	}

	// 遍历区块中的每个交易
	for _, tx := range block.Transactions {
		// 检查交易是否是创始区块交易，如果不是，则处理输入
		// 创始区块交易不含实质的输入，也就不对该交易的输入进行处理
		if !tx.IsCoinbase() {
			for _, out := range tx.Vout {
				if len(out.AssetID) == 0 {
					continue
				}

				// 将反汇编脚本格式化为一行打印
				disasm, err := txscript.DisasmString(out.PubKeyHash)
				if err != nil {
					continue
				}

				// 判断资产数据库对象是否存在
				exists, err := ExistsAssetDatabase(db, string(out.AssetID))
				if err != nil || exists { // 报错或者资产已经存在
					continue
				}
				// 文件资产不存在，则创建资产数据库对象
				ad := &AssetDatabase{
					AssetID:  string(out.AssetID), // 资产的唯一标识
					PKScript: disasm,              // 脚本语言
				}
				// 保存上传记录到数据库
				if err := ad.CreateFileDatabase(db); err != nil {
					continue
				}
			}
		}
	}
}
