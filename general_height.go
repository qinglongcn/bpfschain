package bpfschain

import (
	"context"

	"github.com/bpfs/dep2p/streams"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

type heightPayload struct {
	RequesterHeight int // 请求方当前区块高度
}

// SendHeight 向指定的 peer 送本地区块链的高度
func SendHeight(p2p *dep2p.DeP2P, bps *pubsub.DeP2PPubSub, chain *Blockchain, peerId string) error {
	payload := heightPayload{
		RequesterHeight: chain.GetBestHeight(), // 请求方获取本地区块链的高度
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[SendHeight] 编码失败:\t%v", err)
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
		logrus.Errorf("[SendHeight] 序列化失败:\t%v", err)
		return err
	}

	// 发送本地区块链的高度至全节点
	if err := bps.BroadcastWithTopic(PubsubBlockchainGeneralHeightChannel, requestBytes); err != nil {
		logrus.Errorf("[SendHeight] 发送失败:\t%v", err)
		return err
	}

	return nil
}

// HandleHeight 处理接收到的区块链高度(全节点)
func HandleHeight(ctx context.Context, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	payload := new(heightPayload)
	if err := DecodeFromBytes(request.Payload, &payload); err != nil {
		logrus.Errorf("[HandleHeight] 解码失败:\t%v", err)
		return
	}

	// 获取本地区块链的高度
	bestHeight := chain.GetBestHeight()

	// 本地区块链的高度小于请求方高度
	if bestHeight < payload.RequesterHeight {
		peers := pubsub.ListPeers(PubsubBlockchainFullnodesInitializeChannel)

		// 检查发送者是否在已知对等节点列表中
		senderIsPeer := false
		for _, peer := range peers {
			if peer.String() == request.Message.Sender {
				senderIsPeer = true
				break
			}
		}

		if !senderIsPeer {
			// 如果发送者不在已知对等节点列表中，则忽略该请求
			return
		}

		// 发送获取区块的请求
		if err := SendGetBlocks(p2p, pubsub, request.Message.Sender, bestHeight); err != nil {
			logrus.Errorf("[HandleHeight] 发送获取区块的请求失败:\t%v", err)
		}

		// 本地区块链的高度大于请求方高度
	} else if bestHeight > payload.RequesterHeight {
		// 向指定的 peer 送本地区块链的高度
		if err := SendHeight(p2p, pubsub, chain, request.Message.Sender); err != nil {
			logrus.Errorf("[HandleHeight] 向指定的 peer 送本地区块链的高度失败:\t%v", err)
		}
	}
}
