package bpfschain

import (
	"bytes"
	"context"
	"encoding/hex"
	"time"

	"github.com/bpfs/dep2p/streams"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

type invPayload struct {
	Items [][]byte
}

// SendInvBlock 向指定的 peer 发送区块信息，包含了区块的哈希值
// items [][]byte	当前节点的所有块的哈希
func SendInvBlock(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, peerId string, items [][]byte) error {
	payload := invPayload{
		Items: items,
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[SendInvBlock] 编码失败:\t%v", err)
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
		logrus.Errorf("[SendInvBlock] 序列化失败:\t%v", err)
		return err
	}

	// 发送交易或区块信息
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainGeneralInvBlockChannel, requestBytes); err != nil {
		logrus.Errorf("[SendInvBlock] 发送失败:\t%v", err)
		return err
	}

	return nil
}

// HandleInvBlock 处理接收到的区块信息
func HandleInvBlock(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, memoryPool *MemoryPool, request *streams.RequestMessage) {
	if len(request.Payload) == 0 {
		return
	}

	payload := new(invPayload)
	err := DecodeFromBytes(request.Payload, &payload)
	if err != nil {
		logrus.Errorf("[HandleInvBlock] 解码失败:\t%v", err)
		return
	}

	if len(payload.Items) >= 1 {
		for _, blockHash := range payload.Items {
			// 向指定的 peer 发送获取区块数据的请求
			if err := SendGetDataBlock(p2p, pubsub, request.Message.Sender, blockHash, opt.IsMinerNode); err != nil {
				logrus.Errorf("[HandleInvBlock] 向指定的 peer 发送获取区块数据的请求失败:\t%v", err)
				continue
			}

			// 检查下收到的block的hash是否存在于待交换列表blocksInTransit
			for _, b := range memoryPool.BlocksInTransit {
				if !bytes.Equal(b, blockHash) {
					memoryPool.BlocksInTransit = append(memoryPool.BlocksInTransit, b)
				}
			}

			time.Sleep(500 * time.Millisecond) // 阻塞 0.5 秒钟，避免高并发
		}
	}
}

// SendMiningInvTx 向指定的 peer 发送交易信息，包含了交易的哈希值(全节点)
// items [][]byte	当前节点的所有块的哈希或交易的哈希
func SendMiningInvTx(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, peerId string, items [][]byte) error {
	payload := invPayload{
		Items: items,
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[SendMiningInvTx] 编码失败:\t%v", err)
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
		logrus.Errorf("[SendMiningInvTx] 序列化失败:\t%v", err)
		return err
	}

	// 发送交易清单(矿工节点)
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainMiningInvTxChannel, requestBytes); err != nil {
		logrus.Errorf("[SendMiningInvTx] 发送失败:\t%v", err)
		return err
	}

	logrus.Printf("[SendMiningInvTx]-------- 开始-------- ")
	logrus.Printf("消息类型:\n%+v", srm.Message.Type)
	logrus.Printf("发送方ID:\n%+v", srm.Message.Sender)
	logrus.Printf("接收方ID:\n%+v", srm.Message.Receiver)
	logrus.Printf("发送内容:\n%+v", items)
	logrus.Printf("[SendMiningInvTx]-------- 结束-------- \n\n")

	return nil
}

// HandleMiningInvTx 处理接收到的交易信息(矿工节点)
func HandleMiningInvTx(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	logrus.Printf("[HandleMiningInvTx]-------- 开始-------- ")
	logrus.Printf("%+v", request)
	logrus.Printf("request.Payload\t%+v", len(request.Payload))
	logrus.Printf("[HandleMiningInvTx]-------- 结束-------- \n\n")

	payload := new(invPayload)
	if err := DecodeFromBytes(request.Payload, &payload); err != nil {
		logrus.Errorf("[HandleMiningInvTx] 解码失败:\t%v", err)
		// pool.Wg.Done()

		return
	}

	if len(payload.Items) == 0 {
		// pool.Wg.Done()

		return
	}

	// counter := false
	for _, txID := range payload.Items {
		if pool.Pending[hex.EncodeToString(txID)].ID == nil {
			// 向指定的 peer 发送获取交易数据的请求
			if err := SendFullnodesGetDataTx(p2p, pubsub, pool, request.Message.Sender, txID, opt.IsMinerNode); err != nil {
				logrus.Errorf("[HandleInvTx] 向指定的 peer 发送获取交易数据的请求失败:\t%v", err)
			}
			// counter = true
		} else {

			// 从内存池中获取该交易
			tx := pool.Pending[hex.EncodeToString(txID)]
			// 将交易从一个队列移到另一个队列
			pool.Move(&tx, "queued")
			// 立即挖出排队中的所有交易
			MineTx(opt, p2p, pubsub, chain, pool, pool.Queued, BusinessDbPath)
		}
	}
	// 重新请求交易
	// if !counter {
	// 	pool.Wg.Done()
	// }
}
