package bpfschain

import (
	"encoding/hex"
	"fmt"
	"testing"

	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

/**
这个测试方法 TestCheckPkScriptStandard 旨在测试 checkPkScriptStandard 函数。测试通过构建不同类型的脚本，以确保 checkPkScriptStandard 函数能够正确地识别它们是否符合标准格式。

初始化公钥：测试开始时，生成四个公钥，并将它们的压缩形式序列化后存储在 pubKeys 列表中。

定义测试用例：方法中定义了一系列的测试用例。每个测试用例包括：

name: 测试的描述。
script: 使用 txscript.ScriptBuilder 构建的特定脚本。这个脚本可以包含操作码（如 OP_2, OP_CHECKMULTISIG 等）和数据（这里是之前生成的公钥）。
isStandard: 表示该脚本是否应被认为是标准的。
测试用例的说明：

多签名脚本：如 "key1 and key2"、"key1 or key2" 和 "escrow" 是典型的多签名脚本，表示需要多个密钥中的一部分来签名交易。
非标准脚本：如 "one of four"、"malformed1" 到 "malformed6" 是构建的非标准脚本，用于测试函数是否能正确识别非标准或格式错误的脚本。
执行测试：

对于每个测试用例，首先生成脚本。
使用 txscript.GetScriptClass 获取脚本的类别。
调用 checkPkScriptStandard 函数检查脚本是否符合标准。
根据 checkPkScriptStandard 的返回结果和测试用例中定义的 isStandard 期望值来确定测试是否通过。
错误处理：如果在构建脚本时遇到错误或者测试结果与预期不符，测试会使用 t.Fatalf 输出错误信息并终止测试。
*/

// TestCheckPkScriptStandard 测试 checkPkScriptStandard API。
func TestCheckPkScriptStandard(t *testing.T) {
	var pubKeys [][]byte
	for i := 0; i < 4; i++ {
		// NewPrivateKey 是 ecdsa.GenerateKey 的包装器，它返回 PrivateKey 而不是普通的 ecdsa.PrivateKey。
		pk, err := btcec.NewPrivateKey()
		if err != nil {
			t.Fatalf("TestCheckPkScriptStandard NewPrivateKey failed: %v",
				err)
			return
		}
		// SerializeCompressed 以 33 字节压缩格式序列化公钥。
		pubKeys = append(pubKeys, pk.PubKey().SerializeCompressed())
	}

	tests := []struct {
		name       string // 测试描述。
		script     *txscript.ScriptBuilder
		isStandard bool
	}{
		{
			"key1 and key2",
			txscript.
				// NewScriptBuilder 返回脚本生成器的新实例。 有关详细信息，请参阅 ScriptBuilder。
				NewScriptBuilder().
				// AddOp 将传递的操作码推送到脚本末尾。 如果推送操作码会导致脚本超出允许的最大脚本引擎大小，则不会修改脚本。
				AddOp(txscript.OP_2).
				// AddData 将传递的数据推送到脚本末尾。 它根据数据的长度自动选择规范操作码。 零长度缓冲区将导致将空数据推送到堆栈 (OP_0)，并且任何大于 MaxScriptElementSize 的数据推送都不会修改脚本，因为脚本引擎不允许这样做。 此外，如果推送数据会导致脚本超出脚本引擎允许的最大大小，则不会修改脚本。
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			true,
		},
		{
			"key1 or key2",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			true,
		},
		{
			"escrow",
			txscript.NewScriptBuilder().AddOp(txscript.OP_2).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddData(pubKeys[2]).
				AddOp(txscript.OP_3).AddOp(txscript.OP_CHECKMULTISIG),
			true,
		},
		{
			"one of four",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddData(pubKeys[2]).AddData(pubKeys[3]).
				AddOp(txscript.OP_4).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed1",
			txscript.NewScriptBuilder().AddOp(txscript.OP_3).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed2",
			txscript.NewScriptBuilder().AddOp(txscript.OP_2).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_3).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed3",
			txscript.NewScriptBuilder().AddOp(txscript.OP_0).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed4",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_0).AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed5",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]).
				AddOp(txscript.OP_CHECKMULTISIG),
			false,
		},
		{
			"malformed6",
			txscript.NewScriptBuilder().AddOp(txscript.OP_1).
				AddData(pubKeys[0]).AddData(pubKeys[1]),
			false,
		},
	}

	for _, test := range tests {
		script, err := test.script.Script()
		if err != nil {
			t.Fatalf("TestCheckPkScriptStandard test '%s' 失败：%v", test.name, err)
			continue
		}
		// GetScriptClass 返回传递的脚本的类。
		// 当脚本未解析时将返回 NonStandardTy。
		scriptClass := txscript.GetScriptClass(script)
		// checkPkScriptStandard 对交易输出脚本（公钥脚本）执行一系列检查，以确保它是“标准”公钥脚本。 标准公钥脚本是一种可识别的形式，对于多重签名脚本，仅包含 1 到 maxStandardMultiSigKeys 个公钥。
		got := checkPkScriptStandard(script, scriptClass)
		if (test.isStandard && got != nil) || (!test.isStandard && got == nil) {

			t.Fatalf("TestCheckPkScriptStandard test '%s' 失败", test.name)
			return
		}
	}

}

func TestXxx(t *testing.T) {
	pk, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("TestCheckPkScriptStandard NewPrivateKey failed: %v", err)
		return
	}

	pubKeys := pk.PubKey().SerializeCompressed()

	scriptBuilder := txscript.NewScriptBuilder().AddOp(txscript.OP_2).AddData(pubKeys).AddOp(txscript.OP_2).AddOp(txscript.OP_CHECKMULTISIG)

	script, err := scriptBuilder.Script()
	if err != nil {
		t.Fatalf("TestCheckPkScriptStandard test 失败：%v", err)
	}
	log.Printf("script:\t%x\n", script)

	scriptClass := txscript.GetScriptClass(script)
	log.Printf("scriptClass:\t%v\n", scriptClass)

	got := checkPkScriptStandard(script, scriptClass)
	if got != nil {
		t.Fatalf("TestCheckPkScriptStandard test 失败:\t %v", got)
	}
}

// 此示例演示手动创建和签署兑换交易。
func TestExampleSignTxOutput(t *testing.T) {
	// 通常，私钥将来自正在使用的任何存储机制，但对于本示例，只需对其进行硬编码。
	privKeyBytes, err := hex.DecodeString("22a47fa09a223f2aa079edf85a7c2" +
		"d4f8720ee63e502ee2869afab7de234b80c")
	if err != nil {
		fmt.Println(err)
		return
	}

	privKey, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

	// NewAddressPubKeyHash 返回新的 AddressPubKeyHash。 pkHash 必须是 20 字节。
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	log.Printf("addr--:\t%x\n", addr)

	// 对于此示例，创建一个假交易，代表通常正在花费的真实交易。 它包含一个以 1 BTC 金额支付给地址的输出。
	// NewMsgTx 返回一条符合 Message 接口的新的比特币交易消息。 返回实例具有默认版本的 TxVersion，并且没有交易输入或输出。 此外，锁定时间设置为零，表示交易立即有效，而不是在未来某个时间。
	originTx := wire.NewMsgTx(wire.TxVersion)
	// NewOutPoint 使用提供的哈希值和索引返回新的比特币交易出点。
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))
	// NewTxIn 返回一个新的比特币交易输入，其中包含之前提供的出点和签名脚本，默认序列为 MaxTxInSequenceNum。
	txIn := wire.NewTxIn(prevOut, []byte{txscript.OP_0, txscript.OP_0}, nil)
	// AddTxIn 将事务输入添加到消息中。
	originTx.AddTxIn(txIn)

	// PayToAddrScript 创建一个新脚本，用于向指定地址支付交易输出。
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		fmt.Println(err)
		return
	}
	log.Printf("script--:\t%x\n", pkScript)

	////////////////////////////////////////////////////////////////////////

	scriptClass := txscript.GetScriptClass(pkScript)
	log.Printf("scriptClass:\t%v\n", scriptClass)
	// 将反汇编脚本格式化为一行打印
	disasm, err := txscript.DisasmString(pkScript)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("脚本反汇编:\t%s\n", disasm)

	////////////////////////////////////////////////////////////////////////

	txOut := wire.NewTxOut(0, pkScript)
	originTx.AddTxOut(txOut)
	originTxHash := originTx.TxHash()

	////////////////////////////////////////////////////////////////////////

	// 创建交易以赎回虚假交易。
	redeemTx := wire.NewMsgTx(wire.TxVersion)

	// 添加兑换交易将花费的输入。 此时没有签名脚本，因为它尚未创建或签名，因此为其提供了 nil 。
	prevOut = wire.NewOutPoint(&originTxHash, 0)
	txIn = wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(txIn)

	// 通常，这将包含资金的实际目的地，但对于这个例子，不必费心。
	txOut = wire.NewTxOut(0, nil)
	redeemTx.AddTxOut(txOut)

	////////////////////////////////////////////////////////////////////////

	// 签署赎回交易。
	lookupKey := func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
		// 通常，此函数将涉及查找所提供地址的私钥，但由于此示例中唯一签名的内容使用与上面的私钥关联的地址，因此只需将其与设置的压缩标志一起返回，因为该地址正在使用关联的压缩公钥。
		//
		// 注意：如果您想证明代码实际上正确签署了交易，请取消注释以下行，该行会故意返回无效的密钥进行签名，这反过来会导致验证签名时脚本执行期间失败。
		//
		// privKey.D.SetInt64(12345)
		//
		return privKey, true, nil
	}
	// 请注意，脚本数据库参数此处为 nil，因为未使用它。 在签署支付脚本哈希交易时必须指定它。
	// SignTxOutput 对给定 tx 的输出 idx 进行签名，以解析 pkScript 中给定的脚本，签名类型为 hashType。 将通过使用给定地址的字符串调用 getKey() 来查找所需的任何密钥。 任何支付脚本哈希签名都将通过调用 getScript 进行类似的查找。 如果提供了 previousScript，则 previousScript 中的结果将以类型相关的方式与新生成的结果合并。 签名脚本。
	sigScript, err := txscript.SignTxOutput(&chaincfg.MainNetParams,
		redeemTx, 0, originTx.TxOut[0].PkScript, txscript.SigHashAll,
		txscript.KeyClosure(lookupKey), nil, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	redeemTx.TxIn[0].SignatureScript = sigScript

	// 通过执行脚本对来证明交易已被有效签名。
	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig |
		txscript.ScriptDiscourageUpgradableNops

	// NewEngine 为提供的公钥脚本、交易和输入索引返回一个新的脚本引擎。 标志根据每个标志提供的描述修改脚本引擎的行为。
	vm, err := txscript.NewEngine(
		originTx.TxOut[0].PkScript,
		redeemTx,
		0,
		flags,
		// StandardVerifyFlags 是执行事务脚本时使用的脚本标志，以强制执行脚本被视为标准所需的附加检查。
		// txscript.StandardVerifyFlags,
		nil,
		nil,
		-1,
		nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Execute 将执行脚本引擎中的所有脚本，如果验证成功则返回 nil，如果发生则返回错误。
	if err := vm.Execute(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("交易成功签署")

	// 输出:
	// 交易成功签署
}
