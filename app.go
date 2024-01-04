package bpfschain

import (
	"context"
	"fmt"
	"os"

	"github.com/bpfs/dep2p"

	"github.com/bpfs/dep2p/pubsub"
	"github.com/sirupsen/logrus"
	"go.uber.org/fx"
)

// BC提供了与BPFSCHAIN交互所需的各种函数
type BC struct {
	ctx    context.Context     // 全局上下文
	opt    *Options            // 选项配置
	p2p    *dep2p.DeP2P        // 网络主机
	pubsub *pubsub.DeP2PPubSub // 网络订阅
	db     *SqliteDB           // 数据库服务
	chain  *Blockchain         // 区块链服务
	pool   *MemoryPool         // 内存池
}

// Open 返回一个新的区块链对象
func Open(opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub) (*BC, error) {
	if opt.IsBlockchain {
		return nil, fmt.Errorf("'%s' 区块链实例已打开", opt.InstanceId)
	}
	// 1. 检查并设置选项
	if err := opt.CheckAndSetOptions(); err != nil {
		return nil, err
	}
	// 2. 本地文件夹
	if err := initDirectories(); err != nil {
		return nil, err
	}
	// 3. 本地数据库
	db, err := NewSqliteDB(BusinessDbPath, DbFile)
	if err != nil {
		return nil, err
	}
	// 3.1 数据库表
	if err := db.InitDBTable(); err != nil {
		return nil, err
	}

	ctx := context.Background()
	bc := &BC{
		ctx:    ctx,
		opt:    opt,
		p2p:    p2p,
		pubsub: pubsub,
		db:     db,
	}

	// fx 配置项
	opts := []fx.Option{
		bc.globalInit(),
		fx.Provide(
			NewMemoryPool, // 新的内存池
			NewBlockchain, // 区块链服务
		),
		fx.Invoke(
			RegisterPubsubProtocol, // 注册订阅
			StartBlockchainNet,     // 启动区块链网络
		),
	}
	opts = append(opts, fx.Populate(
		&bc.ctx,
		&bc.opt,
		&bc.p2p,
		&bc.pubsub,
		&bc.db,
		&bc.chain,
		&bc.pool,
	))
	app := fx.New(opts...)

	opt.IsBlockchain = true // 区块链实例已打开

	// 启动所有长时间运行的 goroutine，例如网络服务器或消息队列消费者。
	return bc, app.Start(bc.ctx)
}

// 全局初始化
func (bc *BC) globalInit() fx.Option {
	return fx.Provide(
		// 获取上下文
		func(lc fx.Lifecycle) context.Context {
			lc.Append(fx.Hook{
				OnStop: func(_ context.Context) error {
					return nil
				},
			})
			return bc.ctx
		},
		func() *Options {
			return bc.opt
		},
		func() *dep2p.DeP2P {
			return bc.p2p
		},
		func() *pubsub.DeP2PPubSub {
			return bc.pubsub
		},
		func() *SqliteDB {
			return bc.db
		},
	)
}

// initDirectories 确保所有预定义的文件夹都存在
func initDirectories() error {
	// 所有需要检查的目录
	directories := []string{
		DB,               // 数据库目录
		Logs,             // 日志目录
		BlockchainDbPath, // 区块链db目录
		BusinessDbPath,   // 业务db目录
	}

	// 遍历每个目录并确保它存在
	for _, dir := range directories {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return nil
}

type NewBlockchainInput struct {
	fx.In

	Opt *Options // 文件存储选项配置
}

type NewBlockchainOutput struct {
	fx.Out
	Chain *Blockchain // 区块链服务
}

func NewBlockchain(lc fx.Lifecycle, input NewBlockchainInput) (out NewBlockchainOutput, err error) {
	blockchain, err := UpdateBlockchainInstance(input.Opt)
	if err != nil {
		logrus.Errorf("[NewBlockchain] 启动失败:\t%v", err)
		return out, err
	}
	out.Chain = blockchain
	return out, nil
}

type StartBlockchainNetInput struct {
	fx.In

	Ctx    context.Context     // 全局上下文
	Opt    *Options            // 文件存储选项配置
	P2P    *dep2p.DeP2P        // BPBC网络主机
	PubSub *pubsub.DeP2PPubSub // BPBC网络订阅
	Chain  *Blockchain         // 区块链服务
	Pool   *MemoryPool         // 内存池
}

// StartBlockchain 启动区块链网络
func StartBlockchainNet(lc fx.Lifecycle, input StartBlockchainNetInput) {
	// 向全节点请求区块信息，以补全本地区块链
	// 每一个节点均有区块链的一个完整副本
	go RequestVersionAndBlocks(input.Ctx, input.Opt, input.P2P, input.PubSub, input.Chain)

	// 启用协程，处理网络节点事件
	go HandleEvents(input.P2P, input.PubSub, input.Chain, input.Pool)
}

// UpdateBlockchainInstance 更新区块链实例
func UpdateBlockchainInstance(opt *Options) (*Blockchain, error) {
	// 为每一个实例创建一个log文件，记录日志信息
	SetLog(opt.InstanceId)

	chain := new(Blockchain)

	// 实例ID
	// chain.InstanceId = opt.InstanceId
	// 根据实例ID检查对应的数据库是否存在
	if Exists(opt.InstanceId) {
		fmt.Printf(" ---- 1 ---- \t%v\t%v\n", opt.InstanceId, Exists(opt.InstanceId))
		// 从数据库中取出最后一个区块的哈希，构建一个区块链实例
		return ContinueBlockchain(opt.InstanceId)
	}

	// 创建一个全新区块链
	chain, err := createBlockchain(opt.GenesisCoinbaseAddress, opt.InstanceId, opt.GenesisCoinbaseData, opt.GenesisCoinbaseValue)
	if err != nil {
		fmt.Printf(" ---- 2 ---- %v \n", err)
		return nil, err
	}

	utxos := UTXOSet{Chain: chain}

	utxos.Compute()
	logrus.Info("初始化区块链成功")

	// 创建全新区块
	return chain, nil
}
