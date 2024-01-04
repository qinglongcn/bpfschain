package bpfschain

import (
	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

// MineTx 从交易池中获取交易并进行挖矿
func MineTx(opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, memorypoolTxs map[string]Transaction, dir string) {
	var txs []*Transaction

	for id := range memorypoolTxs {
		logrus.Infof("tx: %s \n", memorypoolTxs[id].ID)
		tx := memorypoolTxs[id]

		if chain.VerifyTransaction(&tx) {
			txs = append(txs, &tx)
		}
	}

	if len(txs) == 0 {
		logrus.Info("无合法的交易")
		// pool.ClearAll() // 清除内存池中的全部交易
		// pool.Wg.Done()

		return
	}

	// 如果需要立即挖矿，则自己作为矿工立即挖矿
	cbTx := MinerTx(GetAddress(opt.Pub), "", opt.Subsidy)
	txs = append(txs, cbTx)

	// 挖掘新的区块并将其添加到区块链中
	newBlock, err := chain.MineBlock(txs)
	if err != nil {
		// pool.ClearAll() // 清除内存池中的全部交易
		// pool.Wg.Done()

		return
	}

	utxos := UTXOSet{Chain: chain}
	// UTXOs.Compute()
	utxos.Update(newBlock)

	// 	pool.Blocks <- block

	logrus.Info("挖出新的区块")

	// 向指定的 peer 发送交易或区块信息
	// peerId为空，SendInv发布给全网
	if err := SendInvBlock(p2p, pubsub, "", [][]byte{newBlock.Hash}); err != nil {
		logrus.Errorf("[MineTx] 向指定的 peer 发送区块信息失败:\t%s", err.Error())
	}

	pool.ClearAll() // 清除内存池中的全部交易
	pool.Wg.Done()
}
