package bpfschain

import (
	"context"
	"time"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

// RequestVersionAndBlocks 向全节点请求区块数据
func RequestVersionAndBlocks(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain) {
	var ticker *time.Ticker
	if opt.IsFullNode {
		ticker = time.NewTicker(5 * time.Minute) // 全节点时，5分钟的定时器
	} else {
		ticker = time.NewTicker(20 * time.Minute) // 非全节点时，20分钟的定时器
	}
	defer ticker.Stop()

	requestedPeers := make(map[string]time.Time) // 记录节点及其请求时间

	for {
		select {
		case <-ticker.C:
			peers := pubsub.ListPeers(PubsubBlockchainFullnodesInitializeChannel)

			if len(peers) == 0 {
				time.Sleep(10 * time.Second) // 如果没有节点，等待10秒
				continue
			}

			var peerID string
			var chosen bool
			for _, peer := range peers {
				peerID = peer.String()
				requestTime, exists := requestedPeers[peerID]

				// 选择一个不在记录中，或上次请求超过30分钟的节点
				if !exists || time.Since(requestTime) > 30*time.Minute {
					chosen = true
					break
				}
			}

			if !chosen {
				time.Sleep(10 * time.Minute) // 如果没有合适的节点，等待10分钟
				continue
			}

			// 向指定的 peer 送本地区块链的高度
			if err := SendHeight(p2p, pubsub, chain, peerID); err != nil {
				logrus.Errorf("[RequestVersionAndBlocks] 向指定的 peer 发送初始化信息失败:\t%v", err)
				continue
			}

			opt.IsSynchronize = true            // 区块已请求同步
			requestedPeers[peerID] = time.Now() // 记录请求时间
			chosen = false

		case <-ctx.Done():
			return
		}
	}
}

// HandleEvents 处理网络事件
func HandleEvents(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool) {
	for {
		select {
		case block := <-pool.Blocks: // 如果 Blocks 队列新增数据（block数据），全网广播
			// 向指定的 peer 发送一个区块
			if err := SendBlock(p2p, pubsub, block, ""); err != nil {
				logrus.Errorf("[HandleEvents] - block 向指定的 peer 发送一个区块失败:\t%v", err)
			}
		case tnx := <-pool.Transactions: // 如果 Transactions 队列新增数据（Transaction数据），全网广播
			// 向指定的全节点 peer 发送交易数据
			if err := SendFullnodesTx(p2p, pubsub, pool, tnx); err != nil {
				logrus.Errorf("[HandleEvents] 向指定的全节点 peer 发送交易数据失败:\t%v", err)
			}
		}
	}
}
