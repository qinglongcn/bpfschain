package bpfschain

import (
	"bytes"
	"encoding/gob"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/sirupsen/logrus"
)

type RefType int

const (
	RefToken RefType = iota // 只引用TokenValue
	RefAsset                // 只引用AssetInfo
)

var (
	// DOTO: 这个值可能存在问题
	checkSumlength = 4 // 检查钱包地址的位数
)

// TxInput 交易的输入，也代表借方
// 包含的是前一笔交易的一个输出
type TxInput struct {
	ID        []byte  // 前一笔交易的ID
	Vout      int     // 前一笔交易在该笔交易所有输出中的索引（一笔交易可能有多个输出，需要有信息指明具体是哪一个）
	Signature []byte  // 输入数字签名
	PubKey    []byte  // PubKey公钥，是发送者的钱包的公钥，用于解锁输出
	RefType   RefType // 引用类型，指示是引用TokenValue、AssetInfo
}

// TxOutputs 结构体表示一组交易输出
type TxOutputs struct {
	Outputs []TxOutput // 交易输出的切片
}

// TxOutput 结构体表示一个交易输出，包含值和公钥哈希
type TxOutput struct {
	Value      float64 // 交易输出的值，非Token交易为 0
	AssetID    []byte  // 文件资产的唯一标识符，非NFT交易为 nil
	PubKeyHash []byte  // 公钥脚本，它定义了如何花费这些资金
}

// NewTXOutput 创建并返回一个新的交易输出
func NewTXOutput(value float64, assetID []byte, address string) *TxOutput {
	// 创建一个新的交易输出实例，初始化其值和公钥哈希（公钥哈希暂时为空）
	txo := &TxOutput{
		Value:      value,   // 交易输出的值
		AssetID:    assetID, // 文件资产的唯一标识符
		PubKeyHash: nil,     // 公钥脚本，它定义了如何花费这些资金
	}

	// 调用 Lock 方法锁定该交易输出到指定的地址
	txo.Lock(address)

	// 返回新创建的交易输出实例
	return txo
}

// Lock 锁定交易输出到一个指定的地址
func (out *TxOutput) Lock(address string) {
	// 对地址进行Base58解码
	// pubKeyHash := Base58Decode(address)
	// 去除地址的版本和校验和部分，获取公钥哈希
	// pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-checkSumlength] // 计算得到公钥哈希

	// 对地址的字符串编码进行解码，如果 addr 是已知地址类型的有效编码，则返回该地址。
	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 创建一个新脚本，用于向指定地址支付交易输出。
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 设置交易输出的公钥哈希字段，锁定该输出
	out.PubKeyHash = pkScript
}

// IsLockWithKey 检查交易输出是否被给定的公钥哈希锁定
func (out *TxOutput) IsLockWithKey(pubKey []byte) bool {
	// 检查 pubKey 和 out.PubKeyHash 是否非空，以避免潜在的空指针异常。
	if len(pubKey) == 0 || out.PubKeyHash == nil || len(out.PubKeyHash) == 0 {
		return false
	}

	// 对地址的字符串编码进行解码，如果 addr 是已知地址类型的有效编码，则返回该地址。
	pubAddress, err := btcutil.DecodeAddress(GetAddress(pubKey), &chaincfg.MainNetParams)
	if err != nil {
		return false
	}

	// 从脚本中提取公钥
	_, outAddress, _, err := txscript.ExtractPkScriptAddrs(out.PubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return false
	}

	for _, addr := range outAddress {
		if addr.String() == pubAddress.String() {
			return true
		}
	}

	return false
}

// Serialize 方法序列化 TxOutputs 实例为字节切片
func (outs *TxOutputs) Serialize() []byte {
	var buff bytes.Buffer // 创建一个字节缓冲区用于存储序列化的数据

	// 创建一个新的 GOB 编码器实例
	enc := gob.NewEncoder(&buff)
	if err := enc.Encode(outs); err != nil {
		logrus.Panic(err)
	}

	return buff.Bytes()
}

// DeserializeOutputs 反序列化一组交易输出
func DeSerializeOutputs(data []byte) *TxOutputs {
	outputs := new(TxOutputs) // 创建一个 TxOutputs 实例用于存储反序列化的数据

	// 创建一个新的 GOB 解码器实例
	dec := gob.NewDecoder(bytes.NewReader(data))
	// 对字节切片数据进行解码
	if err := dec.Decode(&outputs); err != nil {
		logrus.Panic(err)
	}

	// 返回反序列化后的 TxOutputs 实例
	return outputs
}
