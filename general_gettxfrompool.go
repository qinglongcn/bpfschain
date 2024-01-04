package bpfschain

import (
	"context"
	"time"

	"github.com/bpfs/dep2p/streams"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

type getTxFromPoolPayload struct {
	Count int
}

// MinersEventLoop 挖矿事件循环，用于处理挖矿相关的事件(矿工节点)
func MinersEventLoop(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, pool *MemoryPool) {
	// 秒定时器
	poolCheckTicker := time.NewTicker(time.Second) // 每秒
	defer poolCheckTicker.Stop()

	payload := getTxFromPoolPayload{
		Count: 1, // 每次取一条交易，可以优化为每次取多条交易
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[MinersEventLoop] 编码失败:\t%v", err)
		return
	}

	// 请求消息
	srm := &streams.RequestMessage{
		Payload: payloadBytes,
		Message: &streams.Message{
			Sender: p2p.Host().ID().String(), // 发送方ID
		},
	}

	// 序列化
	requestBytes, err := srm.Marshal()
	if err != nil {
		logrus.Errorf("[MinersEventLoop] 序列化失败:\t%v", err)
		return
	}

	for {
		select {

		case <-poolCheckTicker.C:
			if !opt.IsMinerNode {
				return
			}

			// 挖矿事件交易通道
			if err := pubsub.BroadcastWithTopic(PubsubBlockchainFullnodesGetTxFroMpoolChannel, requestBytes); err != nil {
				logrus.Errorf("[MinersEventLoop] 发送失败:\t%v", err)
				continue
			}

			logrus.Printf("[MinersEventLoop]-------- 开始-------- ")
			logrus.Printf("消息内容:\n%+v", srm.Payload)
			logrus.Printf("发送方ID:\n%+v", srm.Message.Sender)
			logrus.Printf("[MinersEventLoop]-------- 结束-------- \n\n")

			pool.Wg.Add(1)

		case <-ctx.Done():
			return
		}

		// pool.Wg.Wait() // 等待所有任务完成
	}

}

// HandleGetTxFromPool 处理接收到的从交易池获取交易的请求(全节点)
func HandleGetTxFromPool(ctx context.Context, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	logrus.Printf("【HandleGetTxFromPool】-------- 开始-------- ")
	logrus.Printf("%+v", request)
	logrus.Printf("【HandleGetTxFromPool】-------- 结束-------- \n\n")

	payload := new(getTxFromPoolPayload)
	if err := DecodeFromBytes(request.Payload, &payload); err != nil {
		logrus.Errorf("[HandleGetTxFromPool] 解码失败:\t%v", err)
		return
	}

	switch {
	// 如果大于等于需求数量发送指定的数量回复
	case len(pool.Pending) >= payload.Count:
		// 从挂起交易队列中得到指定数量的交易
		txs := pool.GetTransactions(payload.Count)

		// 向指定的 peer 发送交易池库存消息
		if err := SendMiningInvTx(p2p, pubsub, request.Message.Sender, txs); err != nil {
			logrus.Errorf("[HandleGetTxFromPool] - txs 向指定的 peer 发送交易池库存消息失败：%v", err)
		}

	// 如果小于需求数量则发送剩余的全部
	case len(pool.Pending) < payload.Count:
		// 从挂起交易队列中得到剩余的全部交易
		txs := pool.GetTransactions(len(pool.Pending))

		// 向指定的 peer 发送交易池库存消息
		if err := SendMiningInvTx(p2p, pubsub, request.Message.Sender, txs); err != nil {
			logrus.Errorf("[HandleGetTxFromPool] - txs 向指定的 peer 发送交易池库存消息失败：%v", err)
		}

	// 如果剩余为空则发送空的回复
	case len(pool.Pending) == 0:
		if err := SendMiningInvTx(p2p, pubsub, request.Message.Sender, [][]byte{}); err != nil {
			logrus.Errorf("[HandleGetTxFromPool] - [][]byte{}  向指定的 peer 发送交易池库存消息失败:\t%v", err)
		}

	default:
		return
	}
}
