package bpfschain

import (
	"context"
	"encoding/hex"

	"github.com/bpfs/dep2p/streams"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

type getDataPayload struct {
	Id      []byte
	IsMiner bool
}

// SendGetDataBlock 向指定的 peer 发送获取区块数据的请求
func SendGetDataBlock(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, peerId string, id []byte, isMiner bool) error {
	// 发送交易时，考虑是否为矿工节点
	payload := getDataPayload{
		Id:      id,
		IsMiner: isMiner,
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[SendGetDataBlock] 编码失败:\t%v", err)
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
		logrus.Errorf("[SendGetDataBlock] 序列化失败:\t%v", err)
		return err
	}

	// 发送获取区块数据的请求
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainGeneralGetDataBlockChannel, requestBytes); err != nil {
		logrus.Errorf("[SendGetDataBlock] 发送失败:\t%v", err)
		return err
	}

	return nil
}

// HandleGetDataBlock 处理接收到的获取区块数据的请求
func HandleGetDataBlock(ctx context.Context, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	payload := new(getDataPayload)
	err := DecodeFromBytes(request.Payload, &payload)
	if err != nil {
		logrus.Errorf("[HandleGetDataBlock] 解码失败:\t%v", err)
		return
	}

	// 根据区块哈希获取一个区块
	block, err := chain.GetBlock(payload.Id)
	if err != nil {
		return
	}

	// 向指定的 peer 发送一个区块
	if err := SendBlock(p2p, pubsub, block, request.Message.Sender); err != nil {
		logrus.Errorf("[HandleGetDataBlock] 向指定的 peer 发送一个区块失败:\t%v", err)
		return
	}
}

// SendFullnodesGetDataTx 向指定的 peer 发送获取交易数据的请求(矿工节点)
func SendFullnodesGetDataTx(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, pool *MemoryPool, peerId string, id []byte, isMiner bool) error {
	// 发送交易时，考虑是否为矿工节点
	payload := getDataPayload{
		Id:      id,
		IsMiner: isMiner,
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[SendFullnodesGetDataTx] 编码失败:\t%v", err)
		// pool.Wg.Done()

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
		logrus.Errorf("[SendFullnodesGetDataTx] 序列化失败:\t%v", err)
		// pool.Wg.Done()

		return err
	}

	// 发送获取交易数据的请求至全节点
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainFullnodesGetDataTxChannel, requestBytes); err != nil {
		logrus.Errorf("[SendFullnodesGetDataTx] 发送失败:\t%v", err)
		// pool.Wg.Done()

		return err
	}

	logrus.Printf("[SendFullnodesGetDataTx]-------- 开始-------- ")
	logrus.Printf("消息类型:\n%+v", srm.Message.Type)
	logrus.Printf("发送方ID:\n%+v", srm.Message.Sender)
	logrus.Printf("接收方ID:\n%+v", srm.Message.Receiver)
	logrus.Printf("发送内容:\n%+v\t%+v", id, isMiner)
	logrus.Printf("[SendFullnodesGetDataTx]-------- 结束-------- \n\n")

	return nil
}

// HandleFullnodesGetDataTx 处理接收到的获取数据的请求(全节点)
func HandleFullnodesGetDataTx(ctx context.Context, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	logrus.Printf("[HandleFullnodesGetDataTx]-------- 开始-------- ")
	logrus.Printf("%+v", request)
	logrus.Printf("[HandleFullnodesGetDataTx]-------- 结束-------- \n\n")

	payload := new(getDataPayload)
	if err := DecodeFromBytes(request.Payload, &payload); err != nil {
		logrus.Errorf("[HandleFullnodesGetDataTx] 解码失败:\t%v", err)
		return
	}

	// 获取交易的ID
	txID := hex.EncodeToString(payload.Id)

	// 从内存池中获取该交易
	tx := pool.Pending[txID]

	// 如果发送者是矿工，则将交易移动到已排队状态，并通过网络将交易发送给其他节点。
	if payload.IsMiner {

		// 将交易从一个队列移到另一个队列
		pool.Move(&tx, "queued")

		// 从交易池中获取交易并发送给指定的 peer
		if err := SendTxFromPool(p2p, pubsub, request.Message.Sender, &tx); err != nil {
			logrus.Errorf("[HandleFullnodesGetDataTx] - SendTxFromPool 从交易池中获取交易并发送给指定的 peer失败:\t%v", err)
			return
		}
	} else {
		// 如果发送者不是矿工，则直接通过网络将交易发送给其他节点。
		// 向指定的矿工 peer 发送交易数据
		if err := SendMiningTx(p2p, pubsub, pool, request.Message.Sender, &tx); err != nil {
			logrus.Errorf("[HandleFullnodesGetDataTx] 向指定的矿工 peer 发送交易数据失败:\t%v", err)
			return
		}
	}
}
