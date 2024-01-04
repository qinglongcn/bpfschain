package bpfschain

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/sirupsen/logrus"
)

// 交易版本号
const (
	versionTx = 1
	txCost    = 0.03
)

// 定义一个 Gas 权重
// var weightsMap = map[float64]float64{
// 	0.0:  0,
// 	0.25: 0.05,
// 	0.5:  0.1,
// 	0.75: 0.2,
// 	1.0:  0.3,
// 	1.25: 0.4,
// 	1.5:  0.5,
// 	1.75: 0.6,
// 	// ---- 正常区间 ----
// 	2.0:  0.7,
// 	2.25: 0.75,
// 	2.5:  0.8,
// 	2.75: 0.85,
// 	3.0:  0.9,
// 	3.25: 0.95,
// 	3.5:  1.0,
// 	3.75: 1.5,
// 	// ---- 正常区间 ----
// 	4.0:  1.6,
// 	4.25: 1.7,
// 	4.5:  1.8,
// 	4.75: 1.9,
// 	5.0:  2.0,
// }

// TransactionType 定义了不同的交易类型。
type TransactionType int

// 交易类型常量
const (
	Coinbase TransactionType = iota // 空投，不需要确认					纯Token			无签名	没有输入
	Transfer                        // 转账，不需要接收方的确认			纯Token			输入方签名
	Casting                         // 铸造，不需要确认					纯NFT			无签名	没有输入
	Trade                           // 交易，需要交易双方确认			Token + NFT		多签
	Handsel                         // 赠予，不需要接收方的确认			纯NFT			输入方签名
	Destroy                         // 销毁

// Auction                         // 拍卖，一种公开的出价和购买过程
// Bidding                         // 竞价，多方竞价获取资产或服务
// 可添加更多交易类型
)

// TransactionStatus 定义了交易的不同状态。
type TransactionStatus int

// 交易状态常量
const (
	Unconfirmed    TransactionStatus = iota // 交易已创建但未被确认
	Confirmed                               // 交易已被确认
	PendingPayment                          // 等待支付
	PaymentFailed                           // 支付失败
	PendingReceipt                          // 等待接收
	Completed                               // 交易已完成
	Revoked                                 // 交易已撤销
	Conflicted                              // 交易冲突
	Expired                                 // 交易已过期
	// 可添加更多状态
)

// PaymentMethod 定义了交易费用的支付方式。
type PaymentMethod int

// 支付方式常量
const (
	PrePaid  PaymentMethod = iota // 预付费，费用在交易发起时支付
	PostPaid                      // 后付费，费用在交易完成时支付
)

// Transaction Tax	交易税
// Value Added Tax	增值税
type TransactionFee struct {
	TransactionTax float64 // 交易税，对交易行为收取的费用
	ValueAddedTax  float64 // 增值税，对资产增值部分收取的费用
	// GasPrice       float64            // 每单位的 Gas 价格，表示执行交易所需的费用的基本单位
	// GasDiscount    float64            // 折扣，0折免费；9折乘0.9付费；10折原价；20要多出一倍的钱。多的销毁，少的系统贴
	// GasWeights     map[string]float64 // 系数，0.0、0.5、1.0、2.0、3.0、3.5、3.75、4.0、4.5、5，对应到输出表，给对方服务费
	Method PaymentMethod // 付款方式
}

// Transaction 结构体代表一个交易，包含交易ID，输入和输出等
type Transaction struct {
	ID          []byte            // 交易ID
	Vin         []TxInput         // 交易输入列表
	Vout        []TxOutput        // 交易输出列表
	TransType   TransactionType   // 交易类型
	Status      TransactionStatus // 交易状态
	Fee         TransactionFee    // 交易费用
	CreatedTime time.Time         // 交易创建时间
	ExpireTime  time.Time         // 交易过期时间
	LockTime    time.Time         // 交易锁定时间，在此时间之前交易不能被处理
	Version     int               // 交易版本号，用于处理交易格式的更新和变更
}

// Hash 方法计算交易的哈希值，返回哈希值的字节切片
func (tx *Transaction) Hash() []byte {
	// 声明一个数组存储哈希值
	var hash [32]byte

	// 创建当前交易的副本
	txCopy := *tx
	// 清空副本的 ID 字段
	txCopy.ID = []byte{}

	// 对副本进行序列化，并计算序列化数据的 SHA256 哈希值
	hash = sha256.Sum256(txCopy.Serialize())
	// 返回哈希值的字节切片
	return hash[:]
}

// IsCoinbase 检查交易是否是 coinbase 交易
// coinbase 交易没有输入
// tx.Vin 只有一个输入，数组长度为1
// tx.Vin[0].Txid 为 []byte{}，因此长度为0
// Vin[0].Vout 设置为 -1
func (tx *Transaction) IsCoinbase() bool {
	return len(tx.Vin) == 1 && len(tx.Vin[0].ID) == 0 && tx.Vin[0].Vout == -1
}

// TrimmedCopy 创建一个修剪后的交易副本（深度拷贝的副本），用于签名用
func (tx *Transaction) TrimmedCopy() Transaction {
	var inputs []TxInput   // 创建一个 TxInput 切片存储剪辑后的输入
	var outputs []TxOutput // 创建一个 TxOutput 切片存储剪辑后的输出

	// 复制所有输入到剪辑副本，但清除签名和公钥字段
	for _, in := range tx.Vin {
		//包含了所有的输入和输出，但是`TXInput.Signature`和`TXIput.PubKey`被设置为`nil`
		//在调用这个方法后，会用引用的前一个交易的输出的PubKeyHash，取代这里的PubKey
		inputs = append(inputs, TxInput{
			ID:        in.ID,
			Vout:      in.Vout,
			Signature: nil,
			PubKey:    nil,
		})
	}
	// 复制所有输出到剪辑副本
	for _, out := range tx.Vout {
		outputs = append(outputs, TxOutput{
			Value:      out.Value,
			PubKeyHash: out.PubKeyHash,
		})
	}
	// 创建剪辑副本
	txCopy := Transaction{
		ID:   tx.ID,
		Vin:  inputs,
		Vout: outputs,
	}

	return txCopy
}

// Sign 对交易中的每一个输入进行签名，需要把输入所引用的输出交易prevTXs作为参数进行处理
func (tx *Transaction) Sign(priv *ecdsa.PrivateKey, prevTXs map[string]Transaction) {
	if tx.IsCoinbase() {
		return // 创始区块交易没有实际输入，无需签名
	}

	txCopy := tx.TrimmedCopy() // 创建交易的修剪副本，用于签名

	// 迭代副本中的每一个输入，分别进行签名
	for inId, in := range txCopy.Vin {
		prevTX, exists := prevTXs[hex.EncodeToString(in.ID)]
		if !exists {
			logrus.Fatal("ERROR: 引用的输出的交易（作为输入）不正确")
		}

		txCopy.Vin[inId].Signature = nil // 清空副本中的签名字段
		txCopy.Vin[inId].PubKey = prevTX.Vout[in.Vout].PubKeyHash

		dataToSign := txCopy.Hash() // 计算交易副本的哈希，作为签名的数据

		// 使用私钥对数据进行签名
		r, s, err := ecdsa.Sign(rand.Reader, priv, dataToSign)
		if err != nil {
			logrus.Panic(err)
		}
		signature := append(r.Bytes(), s.Bytes()...) // 将签名的两部分合并

		tx.Vin[inId].Signature = signature // 设置原始交易的签名
		tx.Vin[inId].PubKey = nil          // 清空原始交易的公钥字段
	}
}

// Verify 验证交易输入的签名
// 确保每个输入都正确地引用了前一笔交易的输出，并且使用了正确的签名和公钥。
func (tx *Transaction) Verify(prevTXs map[string]Transaction) bool {
	if tx.IsCoinbase() {
		return true // 创始区块交易无需验证
	}

	txCopy := tx.TrimmedCopy() // 创建交易的修剪副本，用于验证
	// 迭代每个输入
	for inId, in := range tx.Vin {
		prevTX, exists := prevTXs[hex.EncodeToString(in.ID)]
		if !exists {
			logrus.Fatal("ERROR: 引用的输出的交易（作为输入）不正确")
		}

		txCopy.Vin[inId].Signature = nil // 清空副本中的签名字段
		txCopy.Vin[inId].PubKey = prevTX.Vout[in.Vout].PubKeyHash

		dataToVerify := txCopy.Hash() // 计算交易副本的哈希，作为验证的数据

		// 解析签名和公钥
		var r, s, x, y big.Int
		sigLen := len(in.Signature)
		r.SetBytes(in.Signature[:(sigLen / 2)])
		s.SetBytes(in.Signature[(sigLen / 2):])

		// 从脚本中提取公钥
		scriptClass, addrs, _, err := txscript.ExtractPkScriptAddrs(
			in.PubKey, &chaincfg.MainNetParams)
		if err != nil {
			return false
		}

		if len(addrs) == 0 {
			return false
		}

		var rawPubKey ecdsa.PublicKey
		switch scriptClass {
		case txscript.PubKeyHashTy: // P2PKH
			// 对于P2PKH，地址是公钥的RIPEMD160(SHA256(pubKey))散列

			// 返回将地址插入 txout 脚本时要使用的地址的原始字节。
			addresses := addrs[0].ScriptAddress()
			// 对地址进行Base58解码
			pubKeyHash := Base58Decode(addresses)
			// 去除地址的版本和校验和部分，获取公钥哈希
			pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-checkSumlength] // 计算得到公钥哈希

			// 从输入中直接取出公钥数组，解析为一对长度相同的坐标
			keyLen := len(pubKeyHash)
			x.SetBytes(pubKeyHash[:(keyLen / 2)])
			y.SetBytes(pubKeyHash[(keyLen / 2):])

			// 从解析的坐标创建一个rawPubKey（原生态公钥）
			rawPubKey = ecdsa.PublicKey{Curve: elliptic.P256(), X: &x, Y: &y}

		case txscript.ScriptHashTy: // P2SH
			// 对于P2SH，需要额外的信息来恢复公钥
			// 通常，P2SH地址用于多重签名或其他复杂脚本，需要完整的赎回脚本才能验证
			// 因此在这里可能需要额外的逻辑来处理P2SH

			return false // 暂时不支持P2SH，直接返回false
		// 处理其他类型的scriptClass
		default:
			return false // 不支持的或未知的scriptClass
		}

		// 使用公钥验证签名
		if !ecdsa.Verify(&rawPubKey, dataToVerify, &r, &s) {
			return false // 签名验证失败
		}

		txCopy.Vin[inId].PubKey = nil
	}

	return true // 所有输入都通过验证
}

// String 返回交易的可读表示形式，便于调试和日志记录
func (tx *Transaction) String() string {
	// 创建一个字符串切片存储交易的各个部分
	var lines []string
	// 添加交易ID
	lines = append(lines, fmt.Sprintf("---Transaction: %x", tx.ID))

	// 遍历所有输入，添加输入的详细信息
	for i, input := range tx.Vin {
		lines = append(lines, fmt.Sprintf("	Input (%d):", i))
		lines = append(lines, fmt.Sprintf(" 	 	TXID: %x", input.ID))
		lines = append(lines, fmt.Sprintf("		Out: %d", input.Vout))
		lines = append(lines, fmt.Sprintf(" 	 	Signature: %x", input.Signature))
		lines = append(lines, fmt.Sprintf("		PubKey: %x", input.PubKey))
	}
	// 遍历所有输出，添加输出的详细信息
	for i, out := range tx.Vout {
		lines = append(lines, fmt.Sprintf("	Output (%d):", i))
		lines = append(lines, fmt.Sprintf(" 	 	Value: %f", out.Value))
		lines = append(lines, fmt.Sprintf("		PubkeyHash: %x", out.PubKeyHash))
	}

	// 合并所有字符串并返回
	return strings.Join(lines, "\n")
}

// Serialize 将交易序列化为字节切片
func (tx *Transaction) Serialize() []byte {
	// 创建一个缓冲区存储序列化数据
	var buff bytes.Buffer

	// 创建一个新的 GOB 编码器
	enc := gob.NewEncoder(&buff)
	if err := enc.Encode(tx); err != nil {
		logrus.Panic(err)
	}

	return buff.Bytes()
}

// DeserializeTransaction 反序列化交易
func DeserializeTransaction(data []byte) *Transaction {
	transaction := new(Transaction) // 创建一个 Transaction 变量用于存储反序列化的结果

	// 创建一个新的解码器
	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&transaction) // 解码
	if err != nil {
		logrus.Panic(err) // 如果解码出错，抛出异常
	}

	return transaction // 返回反序列化后的交易
}

// MinerTx 创建一个区块链交易，不需要签名
// 挖矿完成后得到输出币数 50.00
func MinerTx(to, data string, subsidy float64) *Transaction {
	if data == "" {
		randData := make([]byte, 24)
		_, err := rand.Read(randData)
		if err != nil {
			logrus.Panic(err)
		}
		data = fmt.Sprintf("%x", randData)
	}
	// 创建交易的输入
	txIn := TxInput{
		ID:        []byte{},     // 前一笔交易的ID
		Vout:      -1,           // 前一笔交易在该笔交易所有输出中的索引
		Signature: nil,          // 输入数字签名
		PubKey:    []byte(data), // PubKey公钥，是发送者的钱包的公钥，用于解锁输出
		RefType:   RefToken,     // 引用类型，TokenValue
	}

	// 创建并返回一个新的交易输出
	txOut := NewTXOutput(subsidy, nil, to)

	// 创建交易
	tx := Transaction{
		ID:   nil,                // 交易ID
		Vin:  []TxInput{txIn},    // 交易输入列表
		Vout: []TxOutput{*txOut}, // 交易输出列表
		// TransType: Coinbase,           // 交易类型(空投)
		// Status:    Confirmed,          // 交易状态(交易已被确认)
		// Fee: TransactionFee{ // 交易费用
		// 	TransactionCost: CalculateTransactionCost(0),    // 交易费用的金额
		// 	CapitalGainsTax: CalculateCapitalGainsTax(0, 0), // 增值税
		// 	GasPrice:        0,                              // 每单位的 Gas 价格，表示执行交易所需的费用的基本单位
		// 	GasDiscount:     0,                              // 折扣，0折免费；9折乘0.9付费；10折原价；20要多出一倍的钱。多的销毁，少的系统贴
		// 	GasWeights:      nil,                            // 系数，0.0、0.5、1.0、2.0、3.0、3.5、3.75、4.0、4.5、5，对应到输出表，给对方服务费
		// 	Method:          PrePaid,                        // 付款方式：预付费
		// },
		// CreatedTime: time.Now(), // 交易创建时间
		// ExpireTime:  time.Now().Add(24 * time.Hour), // 交易过期时间
		// LockTime:    time.Time{},                    // 交易锁定时间，在此时间之前交易不能被处理
		// Version:     versionTx,                      // 交易版本号，用于处理交易格式的更新和变更
	}

	// 计算交易的哈希值作为ID
	tx.ID = tx.Hash()

	// 返回新建的空投交易
	return &tx
}
