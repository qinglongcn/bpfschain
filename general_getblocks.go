package bpfschain

import (
	"context"

	"github.com/bpfs/dep2p/streams"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

type getBlockPayload struct {
	Height int
}

// SendGetBlocks 向指定的 peer 发送获取区块的请求，从指定的高度开始
func SendGetBlocks(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, peerId string, height int) error {
	payload := getBlockPayload{
		Height: height,
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[SendGetBlocks] 编码失败:\t%v", err)
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
		logrus.Errorf("[SendGetBlocks] 序列化失败:\t%v", err)
		return err
	}

	// 发送获取区块的请求
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainGeneralGetBlocksChannel, requestBytes); err != nil {
		logrus.Errorf("[SendGetBlocks] 发送失败:\t%v", err)
		return err
	}

	return nil
}

// HandleGetBlocks 处理接收到的获取区块的请求
func HandleGetBlocks(ctx context.Context, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	payload := new(getBlockPayload)
	if err := DecodeFromBytes(request.Payload, payload); err != nil {
		logrus.Errorf("[HandleGetBlocks] 解码失败:\t%v", err)
		return
	}

	// 获取指定高度之前的所有区块哈希
	blockHashes := chain.GetBlockHashes(payload.Height)
	// 判断是否为空，不要发送空内容
	if len(blockHashes) == 0 {
		return
	}
	// 向指定的 peer 发送交易或区块信息
	if err := SendInvBlock(p2p, pubsub, request.Message.Sender, blockHashes); err != nil {
		logrus.Errorf("[HandleGetBlocks] 向指定的 peer 发送交易或区块信失败:\t%v", err)
	}
}
