// 可能包含一些参考测试，用于确保脚本处理与比特币核心实现保持一致。

package txscript

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// scriptTestName 返回给定参考脚本测试数据的描述性测试名称。
func scriptTestName(test []interface{}) (string, error) {
	// 考虑任何可选的主要见证数据。
	var witnessOffset int
	if _, ok := test[0].([]interface{}); ok {
		witnessOffset++
	}

	// 除了可选的主要见证数据之外，测试还必须至少包含签名脚本、公钥脚本、标志和预期错误。 最后，它可以选择包含注释。
	if len(test) < witnessOffset+4 || len(test) > witnessOffset+5 {
		return "", fmt.Errorf("invalid test length %d", len(test))
	}

	// 如果指定了测试名称，请使用注释，否则，根据签名脚本、公钥脚本和标志构造名称。
	var name string
	if len(test) == witnessOffset+5 {
		name = fmt.Sprintf("test (%s)", test[witnessOffset+4])
	} else {
		name = fmt.Sprintf("test ([%s, %s, %s])", test[witnessOffset],
			test[witnessOffset+1], test[witnessOffset+2])
	}
	return name, nil
}

// 将十六进制字符串解析为 [] 字节。
func parseHex(tok string) ([]byte, error) {
	if !strings.HasPrefix(tok, "0x") {
		return nil, fmt.Errorf("not a hex number")
	}
	return hex.DecodeString(tok[2:])
}

// parseWitnessStack 将编码为十六进制的见证项的 json 数组解析为见证元素的切片。
func parseWitnessStack(elements []interface{}) ([][]byte, error) {
	witness := make([][]byte, len(elements))
	for i, e := range elements {
		witElement, err := hex.DecodeString(e.(string))
		if err != nil {
			return nil, err
		}

		witness[i] = witElement
	}

	return witness, nil
}

// shortFormOps 保存操作码名称到值的映射，以供短格式解析使用。 它在这里声明，因此只需要创建一次。
var shortFormOps map[string]byte

// parseShortForm 将比特币核心参考测试中使用的字符串解析为它来自的脚本。
//
// 如果是临时的，用于这些测试的格式非常简单：
//   - 除推送操作码和未知操作码以外的操作码以 OP_NAME 或仅 NAME 的形式出现
//   - 普通数字被制成推送操作
//   - 以 0x 开头的数字按原样插入到 []byte 中（因此 0x14 是 OP_DATA_20）
//   - 单引号字符串作为数据推送
//   - 其他任何内容都是错误
func parseShortForm(script string) ([]byte, error) {
	// 仅创建一次简短形式的操作码映射。
	if shortFormOps == nil {
		ops := make(map[string]byte)
		for opcodeName, opcodeValue := range OpcodeByName {
			if strings.Contains(opcodeName, "OP_UNKNOWN") {
				continue
			}
			ops[opcodeName] = opcodeValue

			// 名为 OP_# 的操作码不能去掉 OP_ 前缀，否则它们会与普通数字冲突。
			// 此外，由于 OP_FALSE 和 OP_TRUE 分别是 OP_0 和 OP_1 的别名，因此它们具有相同的值，因此请按名称检测它们并允许它们。
			if (opcodeName == "OP_FALSE" || opcodeName == "OP_TRUE") ||
				(opcodeValue != OP_0 && (opcodeValue < OP_1 ||
					opcodeValue > OP_16)) {

				ops[strings.TrimPrefix(opcodeName, "OP_")] = opcodeValue
			}
		}
		shortFormOps = ops
	}

	// Split 只做一个分隔符，因此将所有 \n 和制表符转换为空格。
	script = strings.Replace(script, "\n", " ", -1)
	script = strings.Replace(script, "\t", " ", -1)
	tokens := strings.Split(script, " ")
	builder := NewScriptBuilder()

	for _, tok := range tokens {
		if len(tok) == 0 {
			continue
		}
		// if 解析为普通数字
		if num, err := strconv.ParseInt(tok, 10, 64); err == nil {
			builder.AddInt64(num)
			continue
		} else if bts, err := parseHex(tok); err == nil {
			// 手动连接字节，因为测试代码故意创建太大的脚本，否则会导致构建器出错。
			if builder.err == nil {
				builder.script = append(builder.script, bts...)
			}
		} else if len(tok) >= 2 &&
			tok[0] == '\'' && tok[len(tok)-1] == '\'' {
			builder.AddFullData([]byte(tok[1 : len(tok)-1]))
		} else if opcode, ok := shortFormOps[tok]; ok {
			builder.AddOp(opcode)
		} else {
			return nil, fmt.Errorf("bad token %q", tok)
		}

	}
	return builder.Script()
}

// parseScriptFlags 将提供的标志字符串从参考测试中使用的格式解析为适合在脚本引擎中使用的 ScriptFlags。
func parseScriptFlags(flagStr string) (ScriptFlags, error) {
	var flags ScriptFlags

	sFlags := strings.Split(flagStr, ",")
	for _, flag := range sFlags {
		switch flag {
		case "":
			// Nothing.
		case "CHECKLOCKTIMEVERIFY":
			flags |= ScriptVerifyCheckLockTimeVerify
		case "CHECKSEQUENCEVERIFY":
			flags |= ScriptVerifyCheckSequenceVerify
		case "CLEANSTACK":
			flags |= ScriptVerifyCleanStack
		case "DERSIG":
			flags |= ScriptVerifyDERSignatures
		case "DISCOURAGE_UPGRADABLE_NOPS":
			flags |= ScriptDiscourageUpgradableNops
		case "LOW_S":
			flags |= ScriptVerifyLowS
		case "MINIMALDATA":
			flags |= ScriptVerifyMinimalData
		case "NONE":
			// Nothing.
		case "NULLDUMMY":
			flags |= ScriptStrictMultiSig
		case "NULLFAIL":
			flags |= ScriptVerifyNullFail
		case "P2SH":
			flags |= ScriptBip16
		case "SIGPUSHONLY":
			flags |= ScriptVerifySigPushOnly
		case "STRICTENC":
			flags |= ScriptVerifyStrictEncoding
		case "WITNESS":
			flags |= ScriptVerifyWitness
		case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
			flags |= ScriptVerifyDiscourageUpgradeableWitnessProgram
		case "MINIMALIF":
			flags |= ScriptVerifyMinimalIf
		case "WITNESS_PUBKEYTYPE":
			flags |= ScriptVerifyWitnessPubKeyType
		case "TAPROOT":
			flags |= ScriptVerifyTaproot
		default:
			return flags, fmt.Errorf("invalid flag: %s", flag)
		}
	}
	return flags, nil
}

// parseExpectedResult 将提供的预期结果字符串解析为允许的脚本错误代码。
// 如果不支持预期的结果字符串，则会返回错误。
func parseExpectedResult(expected string) ([]ErrorCode, error) {
	switch expected {
	case "OK":
		return nil, nil
	case "UNKNOWN_ERROR":
		return []ErrorCode{ErrNumberTooBig, ErrMinimalData}, nil
	case "PUBKEYTYPE":
		return []ErrorCode{ErrPubKeyType}, nil
	case "SIG_DER":
		return []ErrorCode{ErrSigTooShort, ErrSigTooLong,
			ErrSigInvalidSeqID, ErrSigInvalidDataLen, ErrSigMissingSTypeID,
			ErrSigMissingSLen, ErrSigInvalidSLen,
			ErrSigInvalidRIntID, ErrSigZeroRLen, ErrSigNegativeR,
			ErrSigTooMuchRPadding, ErrSigInvalidSIntID,
			ErrSigZeroSLen, ErrSigNegativeS, ErrSigTooMuchSPadding,
			ErrInvalidSigHashType}, nil
	case "EVAL_FALSE":
		return []ErrorCode{ErrEvalFalse, ErrEmptyStack}, nil
	case "EQUALVERIFY":
		return []ErrorCode{ErrEqualVerify}, nil
	case "NULLFAIL":
		return []ErrorCode{ErrNullFail}, nil
	case "SIG_HIGH_S":
		return []ErrorCode{ErrSigHighS}, nil
	case "SIG_HASHTYPE":
		return []ErrorCode{ErrInvalidSigHashType}, nil
	case "SIG_NULLDUMMY":
		return []ErrorCode{ErrSigNullDummy}, nil
	case "SIG_PUSHONLY":
		return []ErrorCode{ErrNotPushOnly}, nil
	case "CLEANSTACK":
		return []ErrorCode{ErrCleanStack}, nil
	case "BAD_OPCODE":
		return []ErrorCode{ErrReservedOpcode, ErrMalformedPush}, nil
	case "UNBALANCED_CONDITIONAL":
		return []ErrorCode{ErrUnbalancedConditional,
			ErrInvalidStackOperation}, nil
	case "OP_RETURN":
		return []ErrorCode{ErrEarlyReturn}, nil
	case "VERIFY":
		return []ErrorCode{ErrVerify}, nil
	case "INVALID_STACK_OPERATION", "INVALID_ALTSTACK_OPERATION":
		return []ErrorCode{ErrInvalidStackOperation}, nil
	case "DISABLED_OPCODE":
		return []ErrorCode{ErrDisabledOpcode}, nil
	case "DISCOURAGE_UPGRADABLE_NOPS":
		return []ErrorCode{ErrDiscourageUpgradableNOPs}, nil
	case "PUSH_SIZE":
		return []ErrorCode{ErrElementTooBig}, nil
	case "OP_COUNT":
		return []ErrorCode{ErrTooManyOperations}, nil
	case "STACK_SIZE":
		return []ErrorCode{ErrStackOverflow}, nil
	case "SCRIPT_SIZE":
		return []ErrorCode{ErrScriptTooBig}, nil
	case "PUBKEY_COUNT":
		return []ErrorCode{ErrInvalidPubKeyCount}, nil
	case "SIG_COUNT":
		return []ErrorCode{ErrInvalidSignatureCount}, nil
	case "MINIMALDATA":
		return []ErrorCode{ErrMinimalData}, nil
	case "NEGATIVE_LOCKTIME":
		return []ErrorCode{ErrNegativeLockTime}, nil
	case "UNSATISFIED_LOCKTIME":
		return []ErrorCode{ErrUnsatisfiedLockTime}, nil
	case "MINIMALIF":
		return []ErrorCode{ErrMinimalIf}, nil
	case "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM":
		return []ErrorCode{ErrDiscourageUpgradableWitnessProgram}, nil
	case "WITNESS_PROGRAM_WRONG_LENGTH":
		return []ErrorCode{ErrWitnessProgramWrongLength}, nil
	case "WITNESS_PROGRAM_WITNESS_EMPTY":
		return []ErrorCode{ErrWitnessProgramEmpty}, nil
	case "WITNESS_PROGRAM_MISMATCH":
		return []ErrorCode{ErrWitnessProgramMismatch}, nil
	case "WITNESS_MALLEATED":
		return []ErrorCode{ErrWitnessMalleated}, nil
	case "WITNESS_MALLEATED_P2SH":
		return []ErrorCode{ErrWitnessMalleatedP2SH}, nil
	case "WITNESS_UNEXPECTED":
		return []ErrorCode{ErrWitnessUnexpected}, nil
	case "WITNESS_PUBKEYTYPE":
		return []ErrorCode{ErrWitnessPubKeyType}, nil
	}

	return nil, fmt.Errorf("unrecognized expected result in test data: %v",
		expected)
}

// createSpendTx 给定传递的签名、见证人和公钥脚本，生成基本支出交易。
func createSpendingTx(witness [][]byte, sigScript, pkScript []byte,
	outputValue int64) *wire.MsgTx {

	coinbaseTx := wire.NewMsgTx(wire.TxVersion)

	outPoint := wire.NewOutPoint(&chainhash.Hash{}, ^uint32(0))
	txIn := wire.NewTxIn(outPoint, []byte{OP_0, OP_0}, nil)
	txOut := wire.NewTxOut(outputValue, pkScript)
	coinbaseTx.AddTxIn(txIn)
	coinbaseTx.AddTxOut(txOut)

	spendingTx := wire.NewMsgTx(wire.TxVersion)
	coinbaseTxSha := coinbaseTx.TxHash()
	outPoint = wire.NewOutPoint(&coinbaseTxSha, 0)
	txIn = wire.NewTxIn(outPoint, sigScript, witness)
	txOut = wire.NewTxOut(outputValue, nil)

	spendingTx.AddTxIn(txIn)
	spendingTx.AddTxOut(txOut)

	return spendingTx
}

// scriptWithInputVal 使用包含目标 pkScript 的输出值包装目标 pkScript。
// 为了正确验证使用嵌套或本机见证程序的输入， inputVal 是必需的。
type scriptWithInputVal struct {
	inputVal int64
	pkScript []byte
}

// testScripts 确保所有通过的脚本测试执行时都具有预期结果，无论是否使用参数指定的签名缓存。
func testScripts(t *testing.T, tests [][]interface{}, useSigCache bool) {
	// 创建签名缓存以仅在请求时使用。
	var sigCache *SigCache
	if useSigCache {
		sigCache = NewSigCache(10)
	}

	for i, test := range tests {
		// "Format is: [[wit..., amount]?, scriptSig, scriptPubKey,
		//    flags, expected_scripterror, ... comments]"

		// 跳过单行注释。
		if len(test) == 1 {
			continue
		}

		// 根据注释和测试数据构建测试的名称。
		name, err := scriptTestName(test)
		if err != nil {
			t.Errorf("TestScripts: invalid test #%d: %v", i, err)
			continue
		}

		var (
			witness  wire.TxWitness
			inputAmt btcutil.Amount
		)

		// 当测试数据的第一个字段是切片时，它包含见证数据，因此其他所有内容都会偏移 1。
		witnessOffset := 0
		if witnessData, ok := test[0].([]interface{}); ok {
			witnessOffset++

			// 如果这是见证测试，则切片中的最后一个元素是输入量，因此我们忽略除最后一个元素之外的所有元素，以便解析见证堆栈。
			strWitnesses := witnessData[:len(witnessData)-1]
			witness, err = parseWitnessStack(strWitnesses)
			if err != nil {
				t.Errorf("%s: can't parse witness; %v", name, err)
				continue
			}

			inputAmt, err = btcutil.NewAmount(witnessData[len(witnessData)-1].(float64))
			if err != nil {
				t.Errorf("%s: can't parse input amt: %v",
					name, err)
				continue
			}

		}

		// 从测试字段中提取并解析签名脚本。
		scriptSigStr, ok := test[witnessOffset].(string)
		if !ok {
			t.Errorf("%s: signature script is not a string", name)
			continue
		}
		scriptSig, err := parseShortForm(scriptSigStr)
		if err != nil {
			t.Errorf("%s: can't parse signature script: %v", name,
				err)
			continue
		}

		// 从测试字段中提取并解析公钥脚本。
		scriptPubKeyStr, ok := test[witnessOffset+1].(string)
		if !ok {
			t.Errorf("%s: public key script is not a string", name)
			continue
		}
		scriptPubKey, err := parseShortForm(scriptPubKeyStr)
		if err != nil {
			t.Errorf("%s: can't parse public key script: %v", name,
				err)
			continue
		}

		// 从测试字段中提取并解析脚本标志。
		flagsStr, ok := test[witnessOffset+2].(string)
		if !ok {
			t.Errorf("%s: flags field is not a string", name)
			continue
		}
		flags, err := parseScriptFlags(flagsStr)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}

		// 从测试字段中提取并解析预期结果。
		//
		// 将预期结果字符串转换为允许的脚本错误代码。
		// 这是必要的，因为 txscript 的错误比参考测试数据更细粒度，因此一些参考测试数据错误映射到不止一种可能性。
		resultStr, ok := test[witnessOffset+3].(string)
		if !ok {
			t.Errorf("%s: result field is not a string", name)
			continue
		}
		allowedErrorCodes, err := parseExpectedResult(resultStr)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}

		// 生成一对交易，使一个交易对从另一个交易，并使用提供的签名和公钥脚本，然后创建一个新引擎来执行脚本。
		tx := createSpendingTx(
			witness, scriptSig, scriptPubKey, int64(inputAmt),
		)
		prevOuts := NewCannedPrevOutputFetcher(scriptPubKey, int64(inputAmt))
		vm, err := NewEngine(
			scriptPubKey, tx, 0, flags, sigCache, nil,
			int64(inputAmt), prevOuts,
		)
		if err == nil {
			err = vm.Execute()
		}

		// 确保预期结果正常时没有错误。
		if resultStr == "OK" {
			if err != nil {
				t.Errorf("%s failed to execute: %v", name, err)
			}
			continue
		}

		// 此时预计会出现错误，因此请确保执行结果与其匹配。
		success := false
		for _, code := range allowedErrorCodes {
			if IsErrorCode(err, code) {
				success = true
				break
			}
		}
		if !success {
			if serr, ok := err.(Error); ok {
				t.Errorf("%s: want error codes %v, got %v", name,
					allowedErrorCodes, serr.ErrorCode)
				continue
			}
			t.Errorf("%s: want error codes %v, got err: %v (%T)",
				name, allowedErrorCodes, err, err)
			continue
		}
	}
}

// TestScripts 确保 script_tests.json 中的所有测试都按照测试数据中定义的预期结果执行。
func TestScripts(t *testing.T) {
	file, err := ioutil.ReadFile("data/script_tests.json")
	if err != nil {
		t.Fatalf("TestScripts: %v\n", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("TestScripts couldn't Unmarshal: %v", err)
	}

	// Run all script tests with and without the signature cache.
	testScripts(t, tests, true)
	testScripts(t, tests, false)
}

// testVecF64ToUint32 正确处理从 JSON 测试数据读取的 float64 到无符号 32 位整数的转换。
// 这是必要的，因为某些测试数据使用 -1 作为表示最大 uint32 的快捷方式，并且负浮点到无符号 int 的直接转换取决于实现，因此不会在所有平台上产生预期值。
// 该函数通过首先转换为 32 位有符号整数，然后转换为 32 位无符号整数来解决该限制，从而在所有平台上产生预期的行为。
func testVecF64ToUint32(f float64) uint32 {
	return uint32(int32(f))
}

// TestTxInvalidTests 确保 tx_invalid.json 中的所有测试都按预期失败。
func TestTxInvalidTests(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_invalid.json")
	if err != nil {
		t.Fatalf("TestTxInvalidTests: %v\n", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("TestTxInvalidTests couldn't Unmarshal: %v\n", err)
	}

	// 形式是:
	//   ["this is a comment "]
	// or:
	//   [[[previous hash, previous index, previous scriptPubKey]...,]
	//	serializedTransaction, verifyFlags]
testloop:
	for i, test := range tests {
		inputs, ok := test[0].([]interface{})
		if !ok {
			continue
		}

		if len(test) != 3 {
			t.Errorf("bad test (bad length) %d: %v", i, test)
			continue

		}
		serializedhex, ok := test[1].(string)
		if !ok {
			t.Errorf("bad test (arg 2 not string) %d: %v", i, test)
			continue
		}
		serializedTx, err := hex.DecodeString(serializedhex)
		if err != nil {
			t.Errorf("bad test (arg 2 not hex %v) %d: %v", err, i,
				test)
			continue
		}

		tx, err := btcutil.NewTxFromBytes(serializedTx)
		if err != nil {
			t.Errorf("bad test (arg 2 not msgtx %v) %d: %v", err,
				i, test)
			continue
		}

		verifyFlags, ok := test[2].(string)
		if !ok {
			t.Errorf("bad test (arg 3 not string) %d: %v", i, test)
			continue
		}

		flags, err := parseScriptFlags(verifyFlags)
		if err != nil {
			t.Errorf("bad test %d: %v", i, err)
			continue
		}

		prevOutFetcher := NewMultiPrevOutFetcher(nil)
		for j, iinput := range inputs {
			input, ok := iinput.([]interface{})
			if !ok {
				t.Errorf("bad test (%dth input not array)"+
					"%d: %v", j, i, test)
				continue testloop
			}

			if len(input) < 3 || len(input) > 4 {
				t.Errorf("bad test (%dth input wrong length)"+
					"%d: %v", j, i, test)
				continue testloop
			}

			previoustx, ok := input[0].(string)
			if !ok {
				t.Errorf("bad test (%dth input hash not string)"+
					"%d: %v", j, i, test)
				continue testloop
			}

			prevhash, err := chainhash.NewHashFromStr(previoustx)
			if err != nil {
				t.Errorf("bad test (%dth input hash not hash %v)"+
					"%d: %v", j, err, i, test)
				continue testloop
			}

			idxf, ok := input[1].(float64)
			if !ok {
				t.Errorf("bad test (%dth input idx not number)"+
					"%d: %v", j, i, test)
				continue testloop
			}
			idx := testVecF64ToUint32(idxf)

			oscript, ok := input[2].(string)
			if !ok {
				t.Errorf("bad test (%dth input script not "+
					"string) %d: %v", j, i, test)
				continue testloop
			}

			script, err := parseShortForm(oscript)
			if err != nil {
				t.Errorf("bad test (%dth input script doesn't "+
					"parse %v) %d: %v", j, err, i, test)
				continue testloop
			}

			var inputValue float64
			if len(input) == 4 {
				inputValue, ok = input[3].(float64)
				if !ok {
					t.Errorf("bad test (%dth input value not int) "+
						"%d: %v", j, i, test)
					continue
				}
			}

			op := wire.NewOutPoint(prevhash, idx)
			prevOutFetcher.AddPrevOut(*op, &wire.TxOut{
				Value:    int64(inputValue),
				PkScript: script,
			})
		}

		for k, txin := range tx.MsgTx().TxIn {
			prevOut := prevOutFetcher.FetchPrevOutput(
				txin.PreviousOutPoint,
			)
			if prevOut == nil {
				t.Errorf("bad test (missing %dth input) %d:%v",
					k, i, test)
				continue testloop
			}
			// 这些注定会失败，因此一旦第一个输入失败，交易就会失败。 （一些测试 txns 也有很好的输入..
			vm, err := NewEngine(prevOut.PkScript, tx.MsgTx(), k,
				flags, nil, nil, prevOut.Value, prevOutFetcher)
			if err != nil {
				continue testloop
			}

			err = vm.Execute()
			if err != nil {
				continue testloop
			}

		}
		t.Errorf("test (%d:%v) succeeded when should fail",
			i, test)
	}
}

// TestTxValidTests 确保 tx_valid.json 中的所有测试均按预期通过。
func TestTxValidTests(t *testing.T) {
	file, err := ioutil.ReadFile("data/tx_valid.json")
	if err != nil {
		t.Fatalf("TestTxValidTests: %v\n", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("TestTxValidTests couldn't Unmarshal: %v\n", err)
	}

	// form is either:
	//   ["this is a comment "]
	// or:
	//   [[[previous hash, previous index, previous scriptPubKey, input value]...,]
	//	serializedTransaction, verifyFlags]
testloop:
	for i, test := range tests {
		inputs, ok := test[0].([]interface{})
		if !ok {
			continue
		}

		if len(test) != 3 {
			t.Errorf("bad test (bad length) %d: %v", i, test)
			continue
		}
		serializedhex, ok := test[1].(string)
		if !ok {
			t.Errorf("bad test (arg 2 not string) %d: %v", i, test)
			continue
		}
		serializedTx, err := hex.DecodeString(serializedhex)
		if err != nil {
			t.Errorf("bad test (arg 2 not hex %v) %d: %v", err, i,
				test)
			continue
		}

		tx, err := btcutil.NewTxFromBytes(serializedTx)
		if err != nil {
			t.Errorf("bad test (arg 2 not msgtx %v) %d: %v", err,
				i, test)
			continue
		}

		verifyFlags, ok := test[2].(string)
		if !ok {
			t.Errorf("bad test (arg 3 not string) %d: %v", i, test)
			continue
		}

		flags, err := parseScriptFlags(verifyFlags)
		if err != nil {
			t.Errorf("bad test %d: %v", i, err)
			continue
		}

		prevOutFetcher := NewMultiPrevOutFetcher(nil)
		for j, iinput := range inputs {
			input, ok := iinput.([]interface{})
			if !ok {
				t.Errorf("bad test (%dth input not array)"+
					"%d: %v", j, i, test)
				continue
			}

			if len(input) < 3 || len(input) > 4 {
				t.Errorf("bad test (%dth input wrong length)"+
					"%d: %v", j, i, test)
				continue
			}

			previoustx, ok := input[0].(string)
			if !ok {
				t.Errorf("bad test (%dth input hash not string)"+
					"%d: %v", j, i, test)
				continue
			}

			prevhash, err := chainhash.NewHashFromStr(previoustx)
			if err != nil {
				t.Errorf("bad test (%dth input hash not hash %v)"+
					"%d: %v", j, err, i, test)
				continue
			}

			idxf, ok := input[1].(float64)
			if !ok {
				t.Errorf("bad test (%dth input idx not number)"+
					"%d: %v", j, i, test)
				continue
			}
			idx := testVecF64ToUint32(idxf)

			oscript, ok := input[2].(string)
			if !ok {
				t.Errorf("bad test (%dth input script not "+
					"string) %d: %v", j, i, test)
				continue
			}

			script, err := parseShortForm(oscript)
			if err != nil {
				t.Errorf("bad test (%dth input script doesn't "+
					"parse %v) %d: %v", j, err, i, test)
				continue
			}

			var inputValue float64
			if len(input) == 4 {
				inputValue, ok = input[3].(float64)
				if !ok {
					t.Errorf("bad test (%dth input value not int) "+
						"%d: %v", j, i, test)
					continue
				}
			}

			op := wire.NewOutPoint(prevhash, idx)
			prevOutFetcher.AddPrevOut(*op, &wire.TxOut{
				Value:    int64(inputValue),
				PkScript: script,
			})
		}

		for k, txin := range tx.MsgTx().TxIn {
			prevOut := prevOutFetcher.FetchPrevOutput(
				txin.PreviousOutPoint,
			)
			if prevOut == nil {
				t.Errorf("bad test (missing %dth input) %d:%v",
					k, i, test)
				continue testloop
			}
			vm, err := NewEngine(prevOut.PkScript, tx.MsgTx(), k,
				flags, nil, nil, prevOut.Value, prevOutFetcher)
			if err != nil {
				t.Errorf("test (%d:%v:%d) failed to create "+
					"script: %v", i, test, k, err)
				continue
			}

			err = vm.Execute()
			if err != nil {
				t.Errorf("test (%d:%v:%d) failed to execute: "+
					"%v", i, test, k, err)
				continue
			}
		}
	}
}

// TestCalcSignatureHash 在ighash.json 中运行比特币核心签名哈希计算测试。
// https://github.com/bitcoin/bitcoin/blob/master/src/test/data/sighash.json
func TestCalcSignatureHash(t *testing.T) {
	file, err := ioutil.ReadFile("data/sighash.json")
	if err != nil {
		t.Fatalf("TestCalcSignatureHash: %v\n", err)
	}

	var tests [][]interface{}
	err = json.Unmarshal(file, &tests)
	if err != nil {
		t.Fatalf("TestCalcSignatureHash couldn't Unmarshal: %v\n",
			err)
	}

	const scriptVersion = 0
	for i, test := range tests {
		if i == 0 {
			// 跳过第一行——仅包含注释。
			continue
		}
		if len(test) != 5 {
			t.Fatalf("TestCalcSignatureHash: Test #%d has "+
				"wrong length.", i)
		}
		var tx wire.MsgTx
		rawTx, _ := hex.DecodeString(test[0].(string))
		err := tx.Deserialize(bytes.NewReader(rawTx))
		if err != nil {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Failed to parse transaction: %v", i, err)
			continue
		}

		subScript, _ := hex.DecodeString(test[1].(string))
		if err := checkScriptParses(scriptVersion, subScript); err != nil {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Failed to parse sub-script: %v", i, err)
			continue
		}

		hashType := SigHashType(testVecF64ToUint32(test[3].(float64)))
		hash, err := CalcSignatureHash(subScript, hashType, &tx,
			int(test[2].(float64)))
		if err != nil {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Failed to compute sighash: %v", i, err)
			continue
		}

		expectedHash, _ := chainhash.NewHashFromStr(test[4].(string))
		if !bytes.Equal(hash, expectedHash[:]) {
			t.Errorf("TestCalcSignatureHash failed test #%d: "+
				"Signature hash mismatch.", i)
		}
	}
}

type inputWitness struct {
	ScriptSig string   `json:"scriptSig"`
	Witness   []string `json:"witness"`
}

type taprootJsonTest struct {
	Tx       string   `json:"tx"`
	Prevouts []string `json:"prevouts"`
	Index    int      `json:"index"`
	Flags    string   `json:"flags"`

	Comment string `json:"comment"`

	Success *inputWitness `json:"success"`

	Failure *inputWitness `json:"failure"`
}

func executeTaprootRefTest(t *testing.T, testCase taprootJsonTest) {
	t.Helper()

	txHex, err := hex.DecodeString(testCase.Tx)
	if err != nil {
		t.Fatalf("unable to decode hex: %v", err)
	}
	tx, err := btcutil.NewTxFromBytes(txHex)
	if err != nil {
		t.Fatalf("unable to decode hex: %v", err)
	}

	var prevOut wire.TxOut

	prevOutFetcher := NewMultiPrevOutFetcher(nil)
	for i, prevOutString := range testCase.Prevouts {
		prevOutBytes, err := hex.DecodeString(prevOutString)
		if err != nil {
			t.Fatalf("unable to decode hex: %v", err)
		}

		var txOut wire.TxOut
		err = wire.ReadTxOut(
			bytes.NewReader(prevOutBytes), 0, 0, &txOut,
		)
		if err != nil {
			t.Fatalf("unable to read utxo: %v", err)
		}

		prevOutFetcher.AddPrevOut(
			tx.MsgTx().TxIn[i].PreviousOutPoint, &txOut,
		)

		if i == testCase.Index {
			prevOut = txOut
		}
	}

	flags, err := parseScriptFlags(testCase.Flags)
	if err != nil {
		t.Fatalf("unable to parse flags: %v", err)
	}

	makeVM := func() *Engine {
		hashCache := NewTxSigHashes(tx.MsgTx(), prevOutFetcher)

		vm, err := NewEngine(
			prevOut.PkScript, tx.MsgTx(), testCase.Index,
			flags, nil, hashCache, prevOut.Value, prevOutFetcher,
		)
		if err != nil {
			t.Fatalf("unable to create vm: %v", err)
		}

		return vm
	}

	if testCase.Success != nil {
		tx.MsgTx().TxIn[testCase.Index].SignatureScript, err = hex.DecodeString(
			testCase.Success.ScriptSig,
		)
		if err != nil {
			t.Fatalf("unable to parse sig script: %v", err)
		}

		var witness [][]byte
		for _, witnessStr := range testCase.Success.Witness {
			witElem, err := hex.DecodeString(witnessStr)
			if err != nil {
				t.Fatalf("unable to parse witness stack: %v", err)
			}

			witness = append(witness, witElem)
		}

		tx.MsgTx().TxIn[testCase.Index].Witness = witness

		vm := makeVM()

		err = vm.Execute()
		if err != nil {
			t.Fatalf("test (%v) failed to execute: "+
				"%v", testCase.Comment, err)
		}
	}

	if testCase.Failure != nil {
		tx.MsgTx().TxIn[testCase.Index].SignatureScript, err = hex.DecodeString(
			testCase.Failure.ScriptSig,
		)
		if err != nil {
			t.Fatalf("unable to parse sig script: %v", err)
		}

		var witness [][]byte
		for _, witnessStr := range testCase.Failure.Witness {
			witElem, err := hex.DecodeString(witnessStr)
			if err != nil {
				t.Fatalf("unable to parse witness stack: %v", err)
			}

			witness = append(witness, witElem)
		}

		tx.MsgTx().TxIn[testCase.Index].Witness = witness

		vm := makeVM()

		err = vm.Execute()
		if err == nil {
			t.Fatalf("test (%v) succeeded, should fail: "+
				"%v", testCase.Comment, err)
		}
	}
}

// TestTaprootReferenceTests 测试我们是否能够正确验证由 bitcoind 项目为 taproot 创建的一组功能生成测试（每个测试的成功和失败路径）：
// https://github.com/bitcoin/bitcoin/blob/master/test/functional/feature_taproot.py.
func TestTaprootReferenceTests(t *testing.T) {
	t.Parallel()

	filePath := "data/taproot-ref"

	testFunc := func(path string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if info.IsDir() {
			t.Logf("skipping dir: %v", info.Name())
			return nil
		}

		testJson, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("unable to read file: %v", err)
		}

		// 所有 JSON 文件都有一个尾随逗号和一个换行符，因此我们将在尝试解析它之前将其删除。
		testJson = bytes.TrimSuffix(testJson, []byte(",\n"))

		var testCase taprootJsonTest
		if err := json.Unmarshal(testJson, &testCase); err != nil {
			return fmt.Errorf("unable to decode json: %v", err)
		}

		testName := fmt.Sprintf(
			"%v:%v", testCase.Comment, filepath.Base(path),
		)
		_ = t.Run(testName, func(t *testing.T) {
			t.Parallel()

			executeTaprootRefTest(t, testCase)
		})

		return nil
	}

	err := filepath.Walk(filePath, testFunc)
	if err != nil {
		t.Fatalf("unable to execute taproot test vectors: %v", err)
	}
}
