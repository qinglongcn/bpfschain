package bpfschain

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bpfs/dep2p/streams"
	"github.com/sirupsen/logrus"
)

// Wallet 添加钱包信息
func (bc *BC) Wallet(priv *ecdsa.PrivateKey, pub []byte, isMinerNode bool) error {
	if priv == nil {
		return errors.New("priv must not be nil")
	}
	if len(pub) == 0 {
		return errors.New("pub must not be empty")
	}

	bc.opt.IsMinerNode = isMinerNode // 是否是矿工节点
	bc.opt.Priv = priv               // 私钥
	bc.opt.Pub = pub                 // 公钥
	bc.opt.IsLogin = true            // 用户已登录

	if bc.opt.IsMinerNode {
		if bc.pubsub.IsSubscribed(PubsubBlockchainMiningInvTxChannel) {
			// 取消订阅 防止之前订阅过，再次订阅
			if err := bc.pubsub.CancelSubscribeWithTopic(PubsubBlockchainMiningInvTxChannel); err != nil {
				logrus.Errorf("取消订阅失败失败：%v \n", err)
			}
		}

		if bc.pubsub.IsSubscribed(PubsubBlockchainMiningTxChannel) {
			// 取消订阅 防止之前订阅过，再次订阅
			if err := bc.pubsub.CancelSubscribeWithTopic(PubsubBlockchainMiningTxChannel); err != nil {
				logrus.Errorf("取消订阅失败失败：%v \n", err)
			}
		}

		// 发送交易清单(矿工节点)
		if err := bc.pubsub.SubscribeWithTopic(PubsubBlockchainMiningInvTxChannel, func(request *streams.RequestMessage) {
			HandleMiningInvTx(bc.ctx, bc.opt, bc.p2p, bc.pubsub, bc.chain, bc.pool, request)
		}, true); err != nil {
			logrus.Errorf("发送交易清单失败：%v \n", err)
			return err
		}

		// 发送交易信息(矿工节点)
		if err := bc.pubsub.SubscribeWithTopic(PubsubBlockchainMiningTxChannel, func(request *streams.RequestMessage) {
			HandleMiningTx(bc.ctx, bc.opt, bc.p2p, bc.pubsub, bc.chain, bc.pool, request)
		}, true); err != nil {
			logrus.Errorf("发送交易信息失败：%v \n", err)
			return err
		}

		// 如果是矿工节点，启用协程，不断发送ping命令给全节点
		if bc.opt.IsBlockchain && bc.opt.IsLogin {
			// 矿工事件循环，以不断地发送一个 ping 给全节点，目的是得到新的交易，为新交易挖矿，并添加到区块链
			go MinersEventLoop(bc.ctx, bc.opt, bc.p2p, bc.pubsub, bc.pool)
		}
	}
	// TODO:如果取消需要另外取消

	return nil
}

// NewTransaction 创建一个资金转移交易并签名（对输入签名）
func (bc *BC) NewTransaction(to string, amount float64) (*Transaction, error) {
	if to == "" {
		return nil, errors.New("to must not be empty")
	}
	if amount <= 0 {
		return nil, errors.New("amount must be greater than 0")
	}

	if !ValidateAddress(to) {
		logrus.Error("目标地址非法 ")
		return nil, fmt.Errorf("目标地址 %v 非法", to)
	}

	utxos := UTXOSet{Chain: bc.chain}
	var inputs []TxInput
	var outputs []TxOutput

	// 计算出发送者公钥的哈希
	pubKeyHash := HashPubKey(bc.opt.Pub)

	// validOutputs为sender为此交易提供的输出，不一定是sender的全部输出
	// acc为sender发出的全部币数，不一定是sender的全部可用币
	acc, validoutputs := utxos.FindSpendableOutputs(pubKeyHash, amount)
	if acc < amount {
		return nil, fmt.Errorf("你没有足够的钱")
	}

	// 构建输入参数（列表）
	for txId, outs := range validoutputs {
		txID, err := hex.DecodeString(txId)
		if err != nil {
			logrus.Panic(err)
		}

		for _, out := range outs {
			input := TxInput{
				ID:        txID,       // 前一笔交易的ID
				Vout:      out,        // 前一笔交易在该笔交易所有输出中的索引
				Signature: nil,        // 输入数字签名
				PubKey:    bc.opt.Pub, // PubKey公钥，是发送者的钱包的公钥，用于解锁输出
				RefType:   RefToken,   // 引用类型，TokenValue
			}
			inputs = append(inputs, input)
		}
	}

	// 构建输出参数（列表），注意，to地址要反编码成实际地址
	outputs = append(outputs, *NewTXOutput(amount, nil, to))
	if acc > amount {
		outputs = append(outputs, *NewTXOutput(acc-amount, nil, GetAddress(bc.opt.Pub))) // 找零，退给sender
	}

	tx := Transaction{ // 初始交易ID设为nil
		ID:        nil,
		Vin:       inputs,
		Vout:      outputs,
		TransType: Transfer,  // 交易类型(转账)
		Status:    Confirmed, // 交易状态(交易已被确认)
		Fee: TransactionFee{ // 交易费用
			TransactionTax: CalculateTransactionCost(amount), // 交易税
			ValueAddedTax:  CalculateCapitalGainsTax(0, 0),   // 增值税
			Method:         PrePaid,                          // 付款方式：预付费
		},
		CreatedTime: time.Now(),                     // 交易创建时间
		ExpireTime:  time.Now().Add(24 * time.Hour), // 交易过期时间
		LockTime:    time.Time{},                    // 交易锁定时间，在此时间之前交易不能被处理
		Version:     versionTx,                      // 交易版本号，用于处理交易格式的更新和变更
	}
	tx.ID = tx.Hash() // 紧接着设置交易的ID，计算交易ID时候，还没对交易进行签名（即签名字段Signature=nil)

	// 利用私钥对交易进行签名，实际上是对交易中的每一个输入进行签名
	utxos.Chain.SignTransaction(bc.opt.Priv, &tx)

	return &tx, nil
}

// BurnToken 创建一个销毁Token的交易
func (bc *BC) BurnToken(amount float64) (*Transaction, error) {
	if amount <= 0 {
		return nil, errors.New("amount must be greater than 0")
	}

	utxos := UTXOSet{Chain: bc.chain}
	var inputs []TxInput
	var outputs []TxOutput

	// 计算出发送者公钥的哈希
	pubKeyHash := HashPubKey(bc.opt.Pub)

	// 获取足够的输出来覆盖销毁的金额
	acc, validOutputs := utxos.FindSpendableOutputs(pubKeyHash, amount)
	if acc < amount {
		return nil, fmt.Errorf("没有足够的Token来销毁")
	}

	// 构建输入
	for txId, outs := range validOutputs {
		txID, err := hex.DecodeString(txId)
		if err != nil {
			logrus.Panic(err)
		}

		for _, out := range outs {
			input := TxInput{
				ID:        txID,
				Vout:      out,
				Signature: nil,
				PubKey:    bc.opt.Pub,
				RefType:   RefToken,
			}
			inputs = append(inputs, input)
		}
	}

	// 构建输出，如果有找零，则返回给用户
	if acc > amount {
		outputs = append(outputs, *NewTXOutput(acc-amount, nil, GetAddress(bc.opt.Pub))) // 找零，退给sender
	}

	// 创建交易
	tx := Transaction{
		ID:   nil,
		Vin:  inputs,
		Vout: outputs,
		// TransType:   Destroy,          // 新增的交易类型
		// Status:      Unconfirmed,      // 初始状态为未确认
		// Fee:         TransactionFee{}, // 设置合适的交易费
		// CreatedTime: time.Now(),
		// ExpireTime:  time.Now().Add(24 * time.Hour),
		// LockTime:    time.Time{},
		// Version:     versionTx,
	}

	// 计算交易ID
	tx.ID = tx.Hash()

	// 利用私钥对交易进行签名，实际上是对交易中的每一个输入进行签名
	utxos.Chain.SignTransaction(bc.opt.Priv, &tx)

	return &tx, nil
}

// CastingTX 创建一个新的 casting 铸造交易
func (bc *BC) CastingTX(assetID []byte, amount float64) (*Transaction, error) {
	if assetID == nil {
		return nil, errors.New("assetID must not be nil")
	}
	if len(assetID) == 0 {
		return nil, errors.New("assetID must not be empty")
	}
	if amount <= 0 {
		return nil, errors.New("amount must be greater than 0")
	}

	utxos := UTXOSet{Chain: bc.chain}
	var inputs []TxInput
	var outputs []TxOutput

	if amount > 0 {
		// 计算出发送者公钥的哈希
		pubKeyHash := HashPubKey(bc.opt.Pub)
		// 获取足够的输出来覆盖销毁的金额
		acc, validOutputs := utxos.FindSpendableOutputs(pubKeyHash, amount)
		if acc < amount {
			return nil, fmt.Errorf("没有足够的Token来铸造")
		}

		// 构建输入
		for txId, outs := range validOutputs {
			txID, err := hex.DecodeString(txId)
			if err != nil {
				logrus.Panic(err)
			}

			for _, out := range outs {
				input := TxInput{
					ID:        txID,
					Vout:      out,
					Signature: nil,
					PubKey:    bc.opt.Pub,
					RefType:   RefToken,
				}
				inputs = append(inputs, input)
			}
		}

		// 构建输出，如果有找零，则返回给用户
		if acc > amount {
			outputs = append(outputs, *NewTXOutput(acc-amount, nil, GetAddress(bc.opt.Pub))) // 找零，退给sender
		}
	}

	// 创建并返回一个新的交易输出
	txOut := NewTXOutput(0, assetID, GetAddress(bc.opt.Pub))
	outputs = append(outputs, *txOut)

	// 创建交易
	tx := Transaction{
		ID:        nil,       // 交易ID
		Vin:       inputs,    // 交易输入列表
		Vout:      outputs,   // 交易输出列表
		TransType: Casting,   // 交易类型(铸造)
		Status:    Confirmed, // 交易状态(交易已被确认)
		Fee: TransactionFee{ // 交易费用
			TransactionTax: CalculateTransactionCost(0),    // 交易税
			ValueAddedTax:  CalculateCapitalGainsTax(0, 0), // 增值税
			Method:         PrePaid,                        // 付款方式：预付费
		},
		CreatedTime: time.Now(),                     // 交易创建时间
		ExpireTime:  time.Now().Add(24 * time.Hour), // 交易过期时间
		LockTime:    time.Time{},                    // 交易锁定时间，在此时间之前交易不能被处理
		Version:     versionTx,                      // 交易版本号，用于处理交易格式的更新和变更
	}

	// 计算交易ID
	tx.ID = tx.Hash()

	// 利用私钥对交易进行签名，实际上是对交易中的每一个输入进行签名
	utxos.Chain.SignTransaction(bc.opt.Priv, &tx)

	return &tx, nil
}

// //////////////////////// TODO //////////////////////
func (bc *BC) GetBalance(pubKeyHash []byte) float64 {
	balance := float64(0)

	utxos := UTXOSet{Chain: bc.chain}

	UTXOs := utxos.FindUnSpentTransactions(pubKeyHash)
	for _, out := range UTXOs {
		balance += out.Value
	}

	logrus.Infof("余额是:\t%f\n", balance)
	return balance
}

// 重建UTXO集
func (bc *BC) ComputeUTXOs() {
	utxos := UTXOSet{Chain: bc.chain}
	utxos.Compute()
	count := utxos.CountTransactions()
	logrus.Infof("重建完成!!!!, utxos集合中现有 %d 个交易", count)
}
