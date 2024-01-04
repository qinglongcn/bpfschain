package bpfschain

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"path/filepath"
)

// Options 是用于创建文件存储对象的参数
type Options struct {
	IsFullNode    bool `optional:"false"  default:"false"` // 是否是全节点，系统预置
	IsMinerNode   bool `optional:"false"  default:"false"` // 是否是矿工节点，付费许可
	IsBlockchain  bool `optional:"false"  default:"false"` // 是否启动区块链
	IsSynchronize bool `optional:"false"  default:"false"` // 是否向全节点同步过区块
	IsLogin       bool `optional:"false"  default:"false"` // 用户是否登录，默认未登录

	InstanceId string // 区块链的实例标识符

	GenesisCoinbaseData    string // 创世区块预留数据
	GenesisCoinbaseAddress string // 创世区块预留地址
	FeeCollectionAddress   string // 交易费用收集地址
	// GenesisCoinbaseValue 是一个常数，表示创世区块中的预留数量。用于营销、团队奖励、合作伙伴激励、社区建设、未来的融资需求等。
	GenesisCoinbaseValue float64
	// subsidy 是一个常数，表示 coinbase 交易中的奖励数量
	Subsidy float64
	// 每单位的 Gas 价格，表示执行交易所需的费用的基本单位
	// 1M是1048576字节
	GasPrice float64
	// 折扣，0折免费；9折乘0.9付费；10折原价；20要多出一倍的钱。多的销毁，少的系统贴
	GasDiscount float64

	Priv *ecdsa.PrivateKey // 私钥
	Pub  []byte            // 公钥
	// pub  *ecdsa.PublicKey  // 公钥
	// PrivateKey []byte // 私钥
	// PublicKey []byte // 公钥
}

// DefaultOptions 设置一个推荐选项列表以获得良好的性能
func DefaultOptions() *Options {
	return &Options{
		// 固定值
		GenesisCoinbaseData:    "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
		GenesisCoinbaseAddress: "1MziZTG1FTCbhrRS5qbPubaCsDBdQ6rPty",
		FeeCollectionAddress:   "1LYV17J4WUzfHy8xjN3ckJ2UCZQfiGFE4w",
		GenesisCoinbaseValue:   1 << 27, // 134217728
		Subsidy:                50,
		GasPrice:               1,
		GasDiscount:            0.9,
		// 初始化
		IsFullNode:    false,
		IsMinerNode:   false,
		IsBlockchain:  false,
		IsSynchronize: false,
		IsLogin:       false,
	}
}

// BuildInstanceId 设置实例ID
func (opt *Options) BuildInstanceId(instanceId ...string) {
	if opt.IsBlockchain { // 区块链实例已打开
		return
	}

	var mac string
	var err error
	if len(instanceId) > 0 {
		mac = instanceId[0]
	} else {
		mac, err = GetPrimaryMACAddress()
		if err != nil {
			// 生成随机字符串作为替代值
			mac, _ = generateRandomString(12) // 可以指定所需的字符串长度
		}
	}
	opt.InstanceId = mac
}

// BuildFullNode 设置为全节点
func (opt *Options) BuildFullNode() {
	if opt.IsBlockchain { // 区块链实例已打开
		return
	}

	opt.IsFullNode = true
}

// BuildRootPath 设置文件根路径
func (opt *Options) BuildRootPath(path string) {
	// 检查路径是否为空
	if path == "" {
		return
	}

	// 检查路径是否是一个绝对路径
	if !filepath.IsAbs(path) {
		// 可以返回错误或记录日志
		return
	}

	// 检查路径是否存在
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// 如果路径不存在，尝试创建它
		if err := os.MkdirAll(path, 0755); err != nil {
			return
		}
	}

	// 设置根路径
	RootPath = path
}

// CheckAndSetOptions 检查并设置选项
func (opt *Options) CheckAndSetOptions() error {
	if opt.IsBlockchain { // 区块链实例已打开
		return fmt.Errorf("'%s' 区块链实例已打开", opt.InstanceId)
	}

	return nil
}
