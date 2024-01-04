// 包含基准测试代码，用于评估与交易脚本相关的不同函数和方法的性能。

package txscript

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

var (
	// manyInputsBenchTx 是一个包含大量输入的交易，对于基准签名哈希计算很有用。
	manyInputsBenchTx wire.MsgTx

	// 用于签名基准测试的模拟先前输出脚本。
	prevOutScript = hexToBytes("a914f5916158e3e2c4551c1796708db8367207ed13bb87")
)

func init() {
	// tx 620f57c92cf05a7f7e7f7d28255d5f7089437bc48e34dcfebf7751d08b7fb8f5
	txHex, err := ioutil.ReadFile("data/many_inputs_tx.hex")
	if err != nil {
		panic(fmt.Sprintf("unable to read benchmark tx file: %v", err))
	}

	txBytes := hexToBytes(string(txHex))
	err = manyInputsBenchTx.Deserialize(bytes.NewReader(txBytes))
	if err != nil {
		panic(err)
	}
}

// BenchmarkCalcSigHash 基准测试计算具有多个输入的交易的所有输入的签名哈希值所需的时间。
func BenchmarkCalcSigHash(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(manyInputsBenchTx.TxIn); j++ {
			_, err := CalcSignatureHash(prevOutScript, SigHashAll,
				&manyInputsBenchTx, j)
			if err != nil {
				b.Fatalf("failed to calc signature hash: %v", err)
			}
		}
	}
}

// BenchmarkCalcWitnessSigHash 基准测试计算具有多个输入的交易的所有输入的见证签名哈希值所需的时间。
func BenchmarkCalcWitnessSigHash(b *testing.B) {
	prevOutFetcher := NewCannedPrevOutputFetcher(prevOutScript, 5)
	sigHashes := NewTxSigHashes(&manyInputsBenchTx, prevOutFetcher)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(manyInputsBenchTx.TxIn); j++ {
			_, err := CalcWitnessSigHash(
				prevOutScript, sigHashes, SigHashAll,
				&manyInputsBenchTx, j, 5,
			)
			if err != nil {
				b.Fatalf("failed to calc signature hash: %v", err)
			}
		}
	}
}

// genComplexScript 返回一个脚本，该脚本由允许的最大操作码的一半组成，后跟适合的最大大小数据推送，但不超过允许的最大脚本大小。
func genComplexScript() ([]byte, error) {
	var scriptLen int
	builder := NewScriptBuilder()
	for i := 0; i < MaxOpsPerScript/2; i++ {
		builder.AddOp(OP_TRUE)
		scriptLen++
	}
	maxData := bytes.Repeat([]byte{0x02}, MaxScriptElementSize)
	for i := 0; i < (MaxScriptSize-scriptLen)/(MaxScriptElementSize+3); i++ {
		builder.AddData(maxData)
	}
	return builder.Script()
}

// BenchmarkScriptParsing 基准测试解析一个非常大的脚本需要多长时间。
func BenchmarkScriptParsing(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	const scriptVersion = 0
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tokenizer := MakeScriptTokenizer(scriptVersion, script)
		for tokenizer.Next() {
			_ = tokenizer.Opcode()
			_ = tokenizer.Data()
			_ = tokenizer.ByteIndex()
		}
		if err := tokenizer.Err(); err != nil {
			b.Fatalf("failed to parse script: %v", err)
		}
	}
}

// BenchmarkDisasmString 基准测试分解一个非常大的脚本需要多长时间。
func BenchmarkDisasmString(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := DisasmString(script)
		if err != nil {
			b.Fatalf("failed to disasm script: %v", err)
		}
	}
}

// BenchmarkIsPubKeyScript 基准测试分析一个非常大的脚本以确定它是否是标准的付费公钥脚本需要多长时间。
func BenchmarkIsPubKeyScript(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsPayToPubKey(script)
	}
}

// BenchmarkIsPubKeyHashScript 基准测试分析一个非常大的脚本以确定它是否是标准的 pay-to-pubkey-hash 脚本需要多长时间。
func BenchmarkIsPubKeyHashScript(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsPayToPubKeyHash(script)
	}
}

// BenchmarkIsPayToScriptHash 基准测试 IsPayToScriptHash 分析一个非常大的脚本需要多长时间。
func BenchmarkIsPayToScriptHash(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsPayToScriptHash(script)
	}
}

// BenchmarkIsMultisigScriptLarge 基准测试 IsMultisigScript 分析一个非常大的脚本需要多长时间。
func BenchmarkIsMultisigScriptLarge(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		isMultisig, err := IsMultisigScript(script)
		if err != nil {
			b.Fatalf("unexpected err: %v", err)
		}
		if isMultisig {
			b.Fatalf("script should NOT be reported as mutisig script")
		}
	}
}

// BenchmarkIsMultisigScript 基准测试 IsMultisigScript 分析 1-of2 多重签名公钥脚本所需的时间。
func BenchmarkIsMultisigScript(b *testing.B) {
	multisigShortForm := "1 " +
		"DATA_33 " +
		"0x030478aaaa2be30772f1e69e581610f1840b3cf2fe7228ee0281cd599e5746f81e " +
		"DATA_33 " +
		"0x0284f4d078b236a9ff91661f8ffbe012737cd3507566f30fd97d25f2b23539f3cd " +
		"2 CHECKMULTISIG"
	pkScript := mustParseShortForm(multisigShortForm)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		isMultisig, err := IsMultisigScript(pkScript)
		if err != nil {
			b.Fatalf("unexpected err: %v", err)
		}
		if !isMultisig {
			b.Fatalf("script should be reported as a mutisig script")
		}
	}
}

// BenchmarkIsMultisigSigScript 基准测试 IsMultisigSigScript 分析一个非常大的脚本需要多长时间。
func BenchmarkIsMultisigSigScriptLarge(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if IsMultisigSigScript(script) {
			b.Fatalf("script should NOT be reported as mutisig sig script")
		}
	}
}

// BenchmarkIsMultisigSigScript 基准测试 IsMultisigSigScript 分析 1-of-2 多重签名公钥脚本（应该是假的）和由 pay-to-script-hash 1-of-2 多重签名赎回脚本组成的签名脚本（应该是错误的）需要多长时间 是真实的）。
func BenchmarkIsMultisigSigScript(b *testing.B) {
	multisigShortForm := "1 " +
		"DATA_33 " +
		"0x030478aaaa2be30772f1e69e581610f1840b3cf2fe7228ee0281cd599e5746f81e " +
		"DATA_33 " +
		"0x0284f4d078b236a9ff91661f8ffbe012737cd3507566f30fd97d25f2b23539f3cd " +
		"2 CHECKMULTISIG"
	pkScript := mustParseShortForm(multisigShortForm)

	sigHex := "0x304402205795c3ab6ba11331eeac757bf1fc9c34bef0c7e1a9c8bd5eebb8" +
		"82f3b79c5838022001e0ab7b4c7662e4522dc5fa479e4b4133fa88c6a53d895dc1d5" +
		"2eddc7bbcf2801 "
	sigScript := mustParseShortForm("DATA_71 " + sigHex + "DATA_71 " +
		multisigShortForm)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if IsMultisigSigScript(pkScript) {
			b.Fatalf("script should NOT be reported as mutisig sig script")
		}
		if !IsMultisigSigScript(sigScript) {
			b.Fatalf("script should be reported as a mutisig sig script")
		}
	}
}

// BenchmarkIsPushOnlyScript 基准测试 IsPushOnlyScript 分析非常大的脚本所需的时间。
func BenchmarkIsPushOnlyScript(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsPushOnlyScript(script)
	}
}

// BenchmarkIsWitnessPubKeyHash 基准测试分析一个非常大的脚本以确定它是否是标准见证公钥哈希脚本所需的时间。
func BenchmarkIsWitnessPubKeyHash(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsPayToWitnessPubKeyHash(script)
	}
}

// BenchmarkIsWitnessScriptHash 基准测试分析一个非常大的脚本以确定它是否是标准见证脚本哈希脚本所需的时间。
func BenchmarkIsWitnessScriptHash(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsPayToWitnessScriptHash(script)
	}
}

// BenchmarkIsNullDataScript 基准测试分析一个非常大的脚本以确定它是否是标准空数据脚本所需的时间。
func BenchmarkIsNullDataScript(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsNullData(script)
	}
}

// BenchmarkIsUnspendable 基准测试 IsUnspendable 分析一个非常大的脚本需要多长时间。
func BenchmarkIsUnspendable(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = IsUnspendable(script)
	}
}

// BenchmarkGetSigOpCount 基准测试计算一个非常大的脚本的签名操作所需的时间。
func BenchmarkGetSigOpCount(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = GetSigOpCount(script)
	}
}

// BenchmarkGetPreciseSigOpCount 使用更精确的计数方法对非常大的脚本的签名操作进行计数所需的时间进行基准测试。
func BenchmarkGetPreciseSigOpCount(b *testing.B) {
	redeemScript, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	// 创建一个假的 pay-to-script-hash 以通过必要的检查，并通过推送生成的“兑换”脚本作为最终数据推送来相应地创建签名脚本，以便基准测试将覆盖 p2sh 路径。
	scriptHash := "0x0000000000000000000000000000000000000001"
	pkScript := mustParseShortForm("HASH160 DATA_20 " + scriptHash + " EQUAL")
	sigScript, err := NewScriptBuilder().AddFullData(redeemScript).Script()
	if err != nil {
		b.Fatalf("failed to create signature script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = GetPreciseSigOpCount(sigScript, pkScript, true)
	}
}

// BenchmarkGetWitnessSigOpCount 对一个非常大的脚本的见证签名操作进行计数所需的时间进行基准测试。
func BenchmarkGetWitnessSigOpCountP2WKH(b *testing.B) {
	pkScript := mustParseShortForm("OP_0 DATA_20 0x0000000000000000000000000000000000000000")
	redeemScript, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	witness := wire.TxWitness{
		redeemScript,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = GetWitnessSigOpCount(nil, pkScript, witness)
	}
}

// BenchmarkGetWitnessSigOpCount 对一个非常大的脚本的见证签名操作进行计数所需的时间进行基准测试。
func BenchmarkGetWitnessSigOpCountNested(b *testing.B) {
	pkScript := mustParseShortForm("HASH160 DATA_20 0x0000000000000000000000000000000000000000 OP_EQUAL")
	sigScript := mustParseShortForm("DATA_22 0x001600000000000000000000000000000000000000000000")
	redeemScript, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	witness := wire.TxWitness{
		redeemScript,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = GetWitnessSigOpCount(sigScript, pkScript, witness)
	}
}

// BenchmarkGetScriptClass 基准测试 GetScriptClass 分析非常大的脚本所需的时间。
func BenchmarkGetScriptClass(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = GetScriptClass(script)
	}
}

// BenchmarkPushedData 基准测试从非常大的脚本中提取推送数据所需的时间。
func BenchmarkPushedData(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := PushedData(script)
		if err != nil {
			b.Fatalf("unexpected err: %v", err)
		}
	}
}

// BenchmarkExtractAtomicSwapDataPushesLarge 基准测试 ExtractAtomicSwapDataPushes 分析一个非常大的脚本需要多长时间。
func BenchmarkExtractAtomicSwapDataPushesLarge(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	const scriptVersion = 0
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := ExtractAtomicSwapDataPushes(scriptVersion, script)
		if err != nil {
			b.Fatalf("unexpected err: %v", err)
		}
	}
}

// BenchmarkExtractAtomicSwapDataPushesLarge 对 ExtractAtomicSwapDataPushes 分析标准原子交换脚本所需的时间进行基准测试。
func BenchmarkExtractAtomicSwapDataPushes(b *testing.B) {
	secret := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	recipient := "0000000000000000000000000000000000000001"
	refund := "0000000000000000000000000000000000000002"
	script := mustParseShortForm(fmt.Sprintf("IF SIZE 32 EQUALVERIFY SHA256 "+
		"DATA_32 0x%s EQUALVERIFY DUP HASH160 DATA_20 0x%s ELSE 300000 "+
		"CHECKLOCKTIMEVERIFY DROP DUP HASH160 DATA_20 0x%s ENDIF "+
		"EQUALVERIFY CHECKSIG", secret, recipient, refund))

	const scriptVersion = 0
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := ExtractAtomicSwapDataPushes(scriptVersion, script)
		if err != nil {
			b.Fatalf("unexpected err: %v", err)
		}
	}
}

// BenchmarkExtractPkScriptAddrsLarge 基准测试分析并可能从非常大的非标准脚本中提取地址所需的时间。
func BenchmarkExtractPkScriptAddrsLarge(b *testing.B) {
	script, err := genComplexScript()
	if err != nil {
		b.Fatalf("failed to create benchmark script: %v", err)
	}

	params := &chaincfg.MainNetParams
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, err := ExtractPkScriptAddrs(script, params)
		if err != nil {
			b.Fatalf("unexpected err: %v", err)
		}
	}
}

// BenchmarkExtractPkScriptAddrs 基准测试分析并可能从典型脚本中提取地址所需的时间。
func BenchmarkExtractPkScriptAddrs(b *testing.B) {
	script := mustParseShortForm("OP_DUP HASH160 " +
		"DATA_20 0x0102030405060708090a0b0c0d0e0f1011121314 " +
		"EQUAL")

	params := &chaincfg.MainNetParams
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _, _, err := ExtractPkScriptAddrs(script, params)
		if err != nil {
			b.Fatalf("unexpected err: %v", err)
		}
	}
}
