// 提供了 txscript 包使用示例的测试代码。

// package txscript_test
package txscript

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// 此示例演示了创建一个向比特币地址付款的脚本。
// 它还打印创建的脚本十六进制并使用 DisasmString 函数显示反汇编的脚本。
// P2PKH（支付给公钥哈希值）
func TestExamplePayToAddrScript(t *testing.T) {
	// 将发送硬币的地址解析为btcutil.Address，这对于确保地址的准确性和确定地址类型很有用。
	// 即将到来的 PayToAddrScript 调用也需要它。
	addressStr := "12gpXQVcCL2qhTNQgyLVdCFG2Qs2px98nV"
	// DecodeAddress 对地址的字符串编码进行解码，如果 addr 是已知地址类型的有效编码，则返回该地址。
	address, err := btcutil.DecodeAddress(addressStr, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("address:\t%v\n", address)

	// 创建一个支付给该地址的公钥脚本。
	// PayToAddrScript 创建一个新脚本，将交易输出支付到指定地址。
	// script, err := PayToAddrScript(address)
	// 调用的 func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error)
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// ScriptAddress 返回将地址插入 txout 脚本时要使用的地址的原始字节。
	pubKeyHash := address.ScriptAddress()
	script, err := NewScriptBuilder().
		AddOp(OP_DUP).AddOp(OP_HASH160).
		AddData(pubKeyHash).
		AddOp(OP_EQUALVERIFY).AddOp(OP_CHECKSIG).
		Script()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("十六进制脚本:\t%x\n", script)

	// 返回传递的脚本是否是标准的 支付到公钥哈希脚本。
	fmt.Printf("%v\n", IsPayToPubKeyHash(script))

	// 将反汇编脚本格式化为一行打印
	disasm, err := DisasmString(script)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("脚本反汇编:\t%s\n", disasm)

	// 输出:
	// 十六进制脚本: 76a914128004ff2fcaf13b2b91eb654b1dc2b674f7ec6188ac
	// 脚本反汇编: OP_DUP OP_HASH160 128004ff2fcaf13b2b91eb654b1dc2b674f7ec61 OP_EQUALVERIFY OP_CHECKSIG
}

// 此示例演示从标准公钥脚本中提取信息。
func TestExampleExtractPkScriptAddrs(t *testing.T) {
	// 从标准的 pay-to-pubkey-hash 脚本开始。
	scriptHex := "76a914128004ff2fcaf13b2b91eb654b1dc2b674f7ec6188ac"
	script, err := hex.DecodeString(scriptHex)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 从脚本中提取并打印详细信息。
	scriptClass, addresses, reqSigs, err := ExtractPkScriptAddrs(
		script, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("脚本类别:", scriptClass)
	fmt.Println("地址:", addresses)
	fmt.Println("所需签名数量:", reqSigs)

	// 输出:
	// 脚本类别: pubkeyhash
	// 地址: [12gpXQVcCL2qhTNQgyLVdCFG2Qs2px98nV]
	// 所需签名数量: 1
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

	// 对于此示例，创建一个假交易，代表通常正在花费的真实交易。 它包含一个以 1 BTC 金额支付给地址的输出。
	originTx := wire.NewMsgTx(wire.TxVersion)
	prevOut := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))
	txIn := wire.NewTxIn(prevOut, []byte{OP_0, OP_0}, nil)
	originTx.AddTxIn(txIn)

	// PayToAddrScript 创建一个新脚本，用于向指定地址支付交易输出。
	pkScript, err := PayToAddrScript(addr)
	if err != nil {
		fmt.Println(err)
		return
	}
	txOut := wire.NewTxOut(100000000, pkScript)
	originTx.AddTxOut(txOut)
	originTxHash := originTx.TxHash()

	// 创建交易以赎回虚假交易。
	redeemTx := wire.NewMsgTx(wire.TxVersion)

	// 添加兑换交易将花费的输入。 此时没有签名脚本，因为它尚未创建或签名，因此为其提供了 nil 。
	prevOut = wire.NewOutPoint(&originTxHash, 0)
	txIn = wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(txIn)

	// 通常，这将包含资金的实际目的地，但对于这个例子，不必费心。
	txOut = wire.NewTxOut(0, nil)
	redeemTx.AddTxOut(txOut)

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
	sigScript, err := SignTxOutput(&chaincfg.MainNetParams,
		redeemTx, 0, originTx.TxOut[0].PkScript, SigHashAll,
		KeyClosure(lookupKey), nil, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	redeemTx.TxIn[0].SignatureScript = sigScript

	// 通过执行脚本对来证明交易已被有效签名。
	flags := ScriptBip16 | ScriptVerifyDERSignatures |
		ScriptStrictMultiSig |
		ScriptDiscourageUpgradableNops
	vm, err := NewEngine(originTx.TxOut[0].PkScript, redeemTx, 0, flags, nil, nil, -1, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := vm.Execute(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("交易成功签署")

	// 输出:
	// 交易成功签署
}

// 此示例演示创建脚本标记生成器实例并使用它来计算脚本包含的操作码数量。
func TestExampleScriptTokenizer(t *testing.T) {
	// 创建一个在示例中使用的脚本。 通常这可能来自其他来源。
	hash160 := btcutil.Hash160([]byte("example"))
	script, err := NewScriptBuilder().AddOp(OP_DUP).
		AddOp(OP_HASH160).AddData(hash160).
		AddOp(OP_EQUALVERIFY).AddOp(OP_CHECKSIG).Script()
	if err != nil {
		fmt.Printf("failed to build script: %v\n", err)
		return
	}

	fmt.Printf("%v", script)

	// 创建一个分词器来迭代脚本并计算操作码的数量。
	const scriptVersion = 0
	var numOpcodes int
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		numOpcodes++
	}
	if tokenizer.Err() != nil {
		fmt.Printf("script failed to parse: %v\n", err)
	} else {
		fmt.Printf("script contains %d opcode(s)\n", numOpcodes)
	}

	// 输出:
	// script contains 5 opcode(s)
}
