/*
# 区块链操作语言（BOL）
*/

// 打印

package bpfschain

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/txscript"
)

// PrintBlockchain 打印区块链
func (bc *BC) PrintBlockchain() {
	iter := bc.chain.Iterator()

	for {
		block := iter.Next()
		fmt.Printf("PrevHash:\t%x\n", block.PrevHash)
		fmt.Printf("Hash:\t\t%x\n", block.Hash)
		fmt.Printf("Height:\t\t%d\n", block.Height)

		pow := NewProof(block)
		validate := pow.Validate()

		fmt.Printf("Valid:\t\t%s\n", strconv.FormatBool(validate))
		for i, tx := range block.Transactions {
			script := tx.Vout[i].PubKeyHash
			disasm, err := txscript.DisasmString(script)
			if err != nil {
				fmt.Println(err)
				return
			}
			fmt.Println("脚本反汇编:", disasm)
			fmt.Println(tx)
		}
		fmt.Println()

		if len(block.PrevHash) == 0 {
			break
		}
	}
}

// PrintBlock 打印区块
func (bc *BC) PrintBlock(blockHash string) error {
	// 将十六进制字符串转换为字节切片
	hashBytes, err := hex.DecodeString(blockHash)
	if err != nil {
		fmt.Println("解码失败:", err)
		return err
	}

	block, err := bc.chain.GetBlock(hashBytes)
	if err != nil {
		return err
	}

	fmt.Printf("Timestamp:\t%s\n", time.Unix(block.Timestamp, 0).String()) // 区块创建的时间戳
	fmt.Printf("Hash:\t\t%x\n", block.Hash)                                // 当前区块的哈希值
	fmt.Printf("PrevHash:\t%x\n", block.PrevHash)                          // 前一个区块的哈希值
	fmt.Printf("Nonce:\t\t%d\n", block.Nonce)                              // 工作量证明算法中的随机数
	fmt.Printf("Height:\t\t%d\n", block.Height)                            // 区块在区块链中的位置高度
	fmt.Printf("MerkleRoot:\t%x\n", block.MerkleRoot)                      // 交易的Merkle树根哈希值
	fmt.Printf("Difficulty:\t%d\n", block.Difficulty)                      // 区块的工作量证明难度
	fmt.Printf("TxCount:\t%d\n", block.TxCount)                            // 区块中的交易数量
	// fmt.Printf("Transactions:\t%v\n", block.Transactions) // 区块中包含的交易列表
	for k, v := range block.Transactions {
		fmt.Printf("\t第【%d】笔交易\n", k+1)
		fmt.Printf("\tID\t\t%x\n", v.ID)                                               // 交易ID
		fmt.Printf("\tTransType\t%x\n", v.TransType)                                   // 交易类型
		fmt.Printf("\tStatus\t\t%x\n", v.Status)                                       // 交易状态
		fmt.Printf("\tFee\t\t%x\n", v.Fee)                                             // 交易费用
		fmt.Printf("\tCreatedTime\t%s\n", v.CreatedTime.Format("2006-01-02 15:04:05")) // 交易创建时间
		fmt.Printf("\tExpireTime\t%s\n", v.ExpireTime.Format("2006-01-02 15:04:05"))   // 交易过期时间
		fmt.Printf("\tLockTime\t%s\n", v.LockTime.Format("2006-01-02 15:04:05"))       // 交易锁定时间，在此时间之前交易不能被处理
		fmt.Printf("\tVersion\t\t%d\n", v.Version)                                     // 交易版本号，用于处理交易格式的更新和变更
		for i, j := range v.Vin {
			fmt.Printf("\t\t>>>\t第【%d】笔输入:\n", i)
			fmt.Printf("\t\tID\t\t%x\n", j.ID)             // 前一笔交易的ID
			fmt.Printf("\t\tVout\t\t%d\n", j.Vout)         // 前一笔交易在该笔交易所有输出中的索引
			fmt.Printf("\t\tSignature\t%x\n", j.Signature) // 输入数字签名
			fmt.Printf("\t\tPubKey\t\t%x\n", j.PubKey)     // PubKey公钥，是发送者的钱包的公钥，用于解锁输出
			fmt.Printf("\t\tRefType\t\t%d\n\n", j.RefType) // 引用类型，指示是引用TokenValue、AssetInfo
		}
		for i, j := range v.Vout {
			fmt.Printf("\t\t<<<\t第【%d】笔输出:\n", i)
			fmt.Printf("\t\tValue\t\t%f\n", j.Value)           // 交易输出的值，非Token交易为 0
			fmt.Printf("\t\tAssetID\t\t%x\n", j.AssetID)       // 文件资产的唯一标识符，非NFT交易为 nil
			fmt.Printf("\t\tPubKeyHash\t%x\n\n", j.PubKeyHash) // 公钥脚本，它定义了如何花费这些资金
		}
	}

	return nil
}
