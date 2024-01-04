package bpfschain

import (
	"context"

	"github.com/bpfs/dep2p/streams"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

// SendFullnodesTx 向指定的全节点 peer 发送交易数据
func SendFullnodesTx(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, pool *MemoryPool, transaction *Transaction) error {
	// 向交易池中添加一个新的交易
	pool.Add(transaction)

	payloadBytes, err := EncodeToBytes(transaction)
	if err != nil {
		logrus.Errorf("[SendFullnodesTx] 编码失败:\t%v", err)
		return err
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
		logrus.Errorf("[SendFullnodesTx] 编码失败:\t%v", err)
		return err
	}

	// 发送交易信息至全节点
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainFullnodesTxChannel, requestBytes); err != nil {
		return err
	}

	logrus.Printf("[SendFullnodesTx]-------- 开始-------- ")
	logrus.Printf("消息类型:\n%+v", srm.Message.Type)
	logrus.Printf("发送方ID:\n%+v", srm.Message.Sender)
	logrus.Printf("接收方ID:\n%+v", srm.Message.Receiver)
	logrus.Printf("发送内容:\ntransaction:\t%+v", transaction)
	logrus.Printf("[SendFullnodesTx]-------- 结束-------- \n\n")

	return nil
}

// HandleFullnodesTx 处理接收到的交易数据(全节点)
func HandleFullnodesTx(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	logrus.Printf("[HandleFullnodesTx]-------- 开始-------- ")
	logrus.Printf("%+v", request)
	logrus.Printf("[HandleFullnodesTx]-------- 结束-------- \n\n")
	tx := new(Transaction)
	if err := DecodeFromBytes(request.Payload, tx); err != nil {
		logrus.Errorf("[HandleFullnodesTx] 解码失败:\t%v", err)
		return
	}

	// 若是全节点，只负责验证交易，并将交易放到内存池中
	if chain.VerifyTransaction(tx) {
		// 如果tx来自本地节点，说明本地节点不是挖矿节点，也没有挖出它，就将它加入到Pending中，成为tx类型的inv，
		// 在其它节点请求tx时候，将本地tx发给对方处理
		pool.Add(tx)

		// if isState.IsMiner { // 当前节点为矿工节点
		// 	// 将交易移到排队队列
		// 	pool.Move(tx, "queued")
		// 	logrus.Info("MINING")

		// 	// 立即挖出排队中的所有交易
		// 	MineTx(p2p, pubsub, chain, pool, pool.Queued, BlockchainDbPath)
		// }
	}
}

// SendTxFromPool 从交易池中获取交易并发送给指定的 peer(全节点)
func SendTxFromPool(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, peerId string, transaction *Transaction) error {
	payloadBytes, err := EncodeToBytes(transaction)
	if err != nil {
		logrus.Errorf("[SendTxFromPool] 编码失败:\t%v", err)
		return err
	}

	// 请求消息
	srm := &streams.RequestMessage{
		// Payload: transaction.Serialize(),
		Payload: payloadBytes,
		Message: &streams.Message{
			Sender:   p2p.Host().ID().String(), // 发送方ID
			Receiver: peerId,                   // 接收方ID
		},
	}

	// 序列化
	requestBytes, err := srm.Marshal()
	if err != nil {
		logrus.Errorf("[SendTxFromPool] 序列化失败:\t%v", err)
		return err
	}

	// 发送交易数据通道
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainMiningTxChannel, requestBytes); err != nil {
		logrus.Errorf("[SendTxFromPool] 发送失败:\t%v", err)
		return err
	}

	return nil
}

// SendMiningTx 向指定的矿工 peer 发送交易数据(全节点)
func SendMiningTx(p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, pool *MemoryPool, peerId string, transaction *Transaction) error {
	// 向交易池中添加一个新的交易
	pool.Add(transaction)

	payloadBytes, err := EncodeToBytes(transaction)
	if err != nil {
		logrus.Errorf("[SendMiningTx] 编码失败:\t%v", err)
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
		logrus.Errorf("[SendMiningTx] 序列化失败:\t%v", err)
		return err
	}

	// 发送交易信息(矿工节点)
	if err := pubsub.BroadcastWithTopic(PubsubBlockchainMiningTxChannel, requestBytes); err != nil {
		logrus.Errorf("[SendMiningTx] 发送失败:\t%v", err)
		return err
	}

	logrus.Printf("[SendMiningTx]-------- 开始-------- ")
	logrus.Printf("消息类型:\n%+v", srm.Message.Type)
	logrus.Printf("发送方ID:\n%+v", srm.Message.Sender)
	logrus.Printf("接收方ID:\n%+v", srm.Message.Receiver)
	logrus.Printf("发送内容:\npeerId:\t%+v\ntransaction:\t%+v", peerId, transaction)
	logrus.Printf("[SendMiningTx]-------- 结束-------- \n\n")

	return nil
}

// HandleMiningTx 处理接收到的交易数据(矿工节点)
func HandleMiningTx(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	logrus.Printf("[HandleMiningTx]-------- 开始-------- ")
	logrus.Printf("%+v", request)
	logrus.Printf("[HandleMiningTx]-------- 结束-------- \n\n")
	tx := new(Transaction)
	if err := DecodeFromBytes(request.Payload, tx); err != nil {
		logrus.Errorf("[HandleMiningTx] 解码失败:\t%v", err)
		// pool.Wg.Done()

		return
	}

	// 验证交易的输入签名
	if !chain.VerifyTransaction(tx) {
		// pool.Wg.Done()
		return
	}

	// 如果tx来自本地节点，说明本地节点不是挖矿节点，也没有挖出它，就将它加入到Pending中，成为tx类型的inv，
	// 在其它节点请求tx时候，将本地tx发给对方处理
	pool.Add(tx)

	// 是否为矿工节点
	if !opt.IsMinerNode {
		// pool.Wg.Done()
		return
	}

	// 将交易移到排队队列
	pool.Move(tx, "queued")

	// 立即挖出排队中的所有交易
	MineTx(opt, p2p, pubsub, chain, pool, pool.Queued, BlockchainDbPath)

}
