package bpfschain

import (
	"context"

	"github.com/bpfs/dep2p"
	"github.com/bpfs/dep2p/pubsub"
	"github.com/bpfs/dep2p/streams"
	"github.com/sirupsen/logrus"
	"go.uber.org/fx"
)

// 订阅
const (
	// 请求区块同步通道 ----------------------

	// 发送最新版本
	PubsubBlockchainGeneralVersionChannel = "pubsub:blockchain/general/version/1.0.0"
	// 发送本地区块链的高度
	PubsubBlockchainGeneralHeightChannel = "pubsub:blockchain/general/height/1.0.0"
	// 发送获取区块的请求
	PubsubBlockchainGeneralGetBlocksChannel = "pubsub:blockchain/general/getblocks/1.0.0"
	// 发送区块信息
	PubsubBlockchainGeneralInvBlockChannel = "pubsub:blockchain/general/inv/block/1.0.0"
	// 发送获取区块数据的请求
	PubsubBlockchainGeneralGetDataBlockChannel = "pubsub:blockchain/general/getdata/block/1.0.0"
	// 发送区块数据
	PubsubBlockchainGeneralBlockChannel = "pubsub:blockchain/general/block/1.0.0"

	// 全节点通道 --------------------

	// 发送初始化信息
	PubsubBlockchainFullnodesInitializeChannel = "pubsub:blockchain/fullnodes/initialize/1.0.0"
	// 发送交易信息
	PubsubBlockchainFullnodesTxChannel = "pubsub:blockchain/fullnodes/tx/1.0.0"
	// 发送获取交易数据的请求
	PubsubBlockchainFullnodesGetDataTxChannel = "pubsub:blockchain/fullnodes/getdata/tx/1.0.0"
	// 挖矿事件交易通道
	PubsubBlockchainFullnodesGetTxFroMpoolChannel = "pubsub:blockchain/fullnodes/gettxfrompool/1.0.0"

	// 矿工通道 --------------------

	// 发送交易清单
	PubsubBlockchainMiningInvTxChannel = "pubsub:blockchain/mining/inv/tx/1.0.0"
	// 发送交易信息
	PubsubBlockchainMiningTxChannel = "pubsub:blockchain/mining/tx/1.0.0"
)

type RegisterPubsubProtocolInput struct {
	fx.In
	Ctx    context.Context     // 全局上下文
	Opt    *Options            // 文件存储选项配置
	P2P    *dep2p.DeP2P        // 网络主机
	PubSub *pubsub.DeP2PPubSub // 网络订阅
	DB     *SqliteDB           // 数据库服务
	Chain  *Blockchain         // 区块链服务

	Pool *MemoryPool // 内存池
}

// RegisterPubsubProtocol 注册订阅
func RegisterPubsubProtocol(lc fx.Lifecycle, input RegisterPubsubProtocolInput) {
	// 发送最新版本
	// 发送：全节点
	// 接收：所有节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainGeneralVersionChannel, func(request *streams.RequestMessage) {
		HandleVersion(input.Ctx, input.Opt, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, true); err != nil {
		logrus.Errorf("发送初始化信息失败：%v \n", err)
	}

	// 发送本地区块链的高度
	// 发送：所有节点
	// 接收：所有节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainGeneralHeightChannel, func(request *streams.RequestMessage) {
		HandleHeight(input.Ctx, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, true); err != nil {
		logrus.Errorf("发送本地区块链的高度失败：%v \n", err)
	}

	// 发送获取区块的请求
	// 发送：所有节点
	// 接收：所有节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainGeneralGetBlocksChannel, func(request *streams.RequestMessage) {
		HandleGetBlocks(input.Ctx, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, true); err != nil {
		logrus.Errorf("发送获取区块的请求失败：%v \n", err)
	}

	// 发送区块信息
	// 发送：所有节点
	// 接收：所有节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainGeneralInvBlockChannel, func(request *streams.RequestMessage) {
		HandleInvBlock(input.Ctx, input.Opt, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, true); err != nil {
		logrus.Errorf("发送区块信息失败：%v \n", err)
	}

	// 发送获取区块数据的请求
	// 发送：所有节点
	// 接收：所有节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainGeneralGetDataBlockChannel, func(request *streams.RequestMessage) {
		HandleGetDataBlock(input.Ctx, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, true); err != nil {
		logrus.Errorf("发送获取区块数据的请求失败：%v \n", err)
	}

	// 发送区块数据
	// 发送：所有节点
	// 接收：所有节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainGeneralBlockChannel, func(request *streams.RequestMessage) {
		HandleBlock(input.Ctx, input.Opt, input.P2P, input.PubSub, input.DB, input.Chain, input.Pool, request)
	}, true); err != nil {
		logrus.Errorf("发送区块数据失败：%v \n", err)
	}

	// 发送初始化信息
	// 发送：所有节点
	// 接收：全节点
	// if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainFullnodesInitializeChannel, func(request *streams.RequestMessage) {
	// 	HandleInit(input.Ctx, input.Opt, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	// }, input.Opt.IsFullNode); err != nil {
	// 	logrus.Errorf("发送初始化信息失败：%v \n", err)
	// }

	// 发送交易信息
	// 发送：所有节点
	// 接收：全节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainFullnodesTxChannel, func(request *streams.RequestMessage) {
		HandleFullnodesTx(input.Ctx, input.Opt, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, input.Opt.IsFullNode); err != nil {
		logrus.Errorf("发送交易数据通道失败：%v \n", err)
	}

	// 发送获取交易数据的请求
	// 发送：矿工节点
	// 接收：全节点
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainFullnodesGetDataTxChannel, func(request *streams.RequestMessage) {
		HandleFullnodesGetDataTx(input.Ctx, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, input.Opt.IsFullNode); err != nil {
		logrus.Errorf("发送获取交易数据的请求失败：%v \n", err)
	}

	// 全节点向矿工节点发送交易清单或交易信息
	if input.Opt.IsFullNode {
		// 发送交易清单(全节点)
		if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainMiningInvTxChannel, func(request *streams.RequestMessage) {
			HandleMiningInvTx(input.Ctx, input.Opt, input.P2P, input.PubSub, input.Chain, input.Pool, request)
		}, false); err != nil {
			logrus.Errorf("发送交易清单失败：%v \n", err)
		}

		// 发送交易信息(全节点)
		if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainMiningTxChannel, func(request *streams.RequestMessage) {
			HandleMiningTx(input.Ctx, input.Opt, input.P2P, input.PubSub, input.Chain, input.Pool, request)
		}, false); err != nil {
			logrus.Errorf("发送交易信息失败：%v \n", err)
		}
	}

	// 挖矿事件交易通道
	if err := input.PubSub.SubscribeWithTopic(PubsubBlockchainFullnodesGetTxFroMpoolChannel, func(request *streams.RequestMessage) {
		HandleGetTxFromPool(input.Ctx, input.P2P, input.PubSub, input.Chain, input.Pool, request)
	}, input.Opt.IsFullNode); err != nil {
		logrus.Errorf("挖矿事件交易通道,失败：%v \n", err)
	}

	lc.Append(fx.Hook{
		OnStop: func(ctx context.Context) error {
			return nil
		},
	})
}
