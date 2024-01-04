// 包含处理脚本字节码的基本函数和方法。

package txscript

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// Bip16Activation 是 BIP0016 在区块链中有效使用的时间戳。 用于确定是否应调用 BIP0016。
// 此时间戳对应于 UTC 2012 年 4 月 1 日 00:00:00。
var Bip16Activation = time.Unix(1333238400, 0)

const (
	// TaprootAnnexTag 是附件的标签。 该值用于在 Tapscript 支出期间识别附件。
	// 如果主根见证堆栈中至少有两个元素，并且最后一个元素的第一个字节与此标记匹配，那么我们会将其提取为不同的项目。
	TaprootAnnexTag = 0x50

	// TaprootLeafMask 是应用于控制块的掩码，用于在使用了 taproot 脚本叶子的情况下提取输出密钥的 y 坐标的叶子版本和奇偶校验。
	TaprootLeafMask = 0xfe
)

// 这些是为各个脚本中的最大值指定的常量。
const (
	MaxOpsPerScript       = 201 // 最大非推送操作数。
	MaxPubKeysPerMultiSig = 20  // 多重签名不能有比这更多的签名。
	MaxScriptElementSize  = 520 // 可推入堆栈的最大字节数。
)

// IsSmallInt 返回操作码是否被视为小整数，即 OP_0 或 OP_1 到 OP_16。
//
// 注意：该函数仅对版本 0 操作码有效。 由于该函数不接受脚本版本，因此其他脚本版本的结果未定义。
func IsSmallInt(op byte) bool {
	return op == OP_0 || (op >= OP_1 && op <= OP_16)
}

// 如果脚本采用标准付费公钥 (P2PK) 格式，则 IsPayToPubKey 返回 true，否则返回 false。
func IsPayToPubKey(script []byte) bool {
	return isPubKeyScript(script)
}

// 如果脚本采用标准支付公钥哈希 (P2PKH) 格式，则 IsPayToPubKeyHash 返回 true，否则返回 false。
func IsPayToPubKeyHash(script []byte) bool {
	return isPubKeyHashScript(script)
}

// 如果脚本采用标准支付脚本哈希 (P2SH) 格式，则 IsPayToScriptHash 返回 true，否则返回 false。
//
// 警告：此函数始终将传递的脚本视为版本 0。
// 如果引入新的脚本版本，则必须非常小心，因为它是一致使用的，不幸的是，截至撰写本文时，在确定之前不会检查脚本版本 如果脚本是 P2SH，这意味着现有规则上的节点将分析新版本脚本，就像它们是版本 0 一样。
func IsPayToScriptHash(script []byte) bool {
	return isScriptHashScript(script)
}

// 如果脚本采用标准付费见证脚本哈希 (P2WSH) 格式，则 IsPayToWitnessScriptHash 返回 true，否则返回 false。
func IsPayToWitnessScriptHash(script []byte) bool {
	return isWitnessScriptHashScript(script)
}

// 如果脚本采用标准付费见证公钥哈希 (P2WKH) 格式，则 IsPayToWitnessPubKeyHash 返回 true，否则返回 false。
func IsPayToWitnessPubKeyHash(script []byte) bool {
	return isWitnessPubKeyHashScript(script)
}

// 如果传递的脚本是标准 pay-to-taproot (PTTR) 脚本，则 IsPayToTaproot 返回 true，否则返回 false。
func IsPayToTaproot(script []byte) bool {
	return isWitnessTaprootScript(script)
}

// 如果传递的脚本是根据传递的见证程序版本编码的有效见证程序，则 IsWitnessProgram 返回 true。
// 见证程序必须是一个小整数（从 0-16），后跟 2-40 字节的推送数据。
func IsWitnessProgram(script []byte) bool {
	return isWitnessProgramScript(script)
}

// 如果传递的脚本是空数据脚本，则 IsNullData 返回 true，否则返回 false。
func IsNullData(script []byte) bool {
	const scriptVersion = 0
	return isNullDataScript(scriptVersion, script)
}

// ExtractWitnessProgramInfo 尝试从传递的脚本中提取见证程序版本以及见证程序本身。
func ExtractWitnessProgramInfo(script []byte) (int, []byte, error) {
	// If at this point, the scripts doesn't resemble a witness program,
	// then we'll exit early as there isn't a valid version or program to
	// extract.
	version, program, valid := extractWitnessProgramInfo(script)
	if !valid {
		return 0, nil, fmt.Errorf("script is not a witness program, " +
			"unable to extract version or witness program")
	}

	return version, program, nil
}

// IsPushOnlyScript 返回传入的脚本是否只按照推送数据的共识定义推送数据。
//
// 警告：此函数始终将传递的脚本视为版本 0。如果引入新的脚本版本，则必须非常小心，因为它是一致使用的，不幸的是，截至撰写本文时，在检查之前不会检查脚本版本
// 如果它是仅推送脚本，这意味着现有规则上的节点将把新版本脚本视为版本 0。
func IsPushOnlyScript(script []byte) bool {
	const scriptVersion = 0
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		// All opcodes up to OP_16 are data push instructions.
		// NOTE: This does consider OP_RESERVED to be a data push instruction,
		// but execution of OP_RESERVED will fail anyway and matches the
		// behavior required by consensus.
		if tokenizer.Opcode() > OP_16 {
			return false
		}
	}
	return tokenizer.Err() == nil
}

// DisasmString 将反汇编脚本格式化为一行打印。 当脚本解析失败时，返回的字符串将包含失败发生点之前的反汇编脚本，并附加字符串'[error]'。 此外，如果调用者想要有关失败的更多信息，则会返回脚本解析失败的原因。
//
// 注意：该函数仅对0版本脚本有效。 由于该函数不接受脚本版本，因此其他脚本版本的结果未定义。
func DisasmString(script []byte) (string, error) {
	const scriptVersion = 0

	var disbuf strings.Builder
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	if tokenizer.Next() {
		disasmOpcode(&disbuf, tokenizer.op, tokenizer.Data(), true)
	}
	for tokenizer.Next() {
		disbuf.WriteByte(' ')
		disasmOpcode(&disbuf, tokenizer.op, tokenizer.Data(), true)
	}
	if tokenizer.Err() != nil {
		if tokenizer.ByteIndex() != 0 {
			disbuf.WriteByte(' ')
		}
		disbuf.WriteString("[error]")
	}
	return disbuf.String(), tokenizer.Err()
}

// removeOpcodeRaw 将在删除与'opcode'匹配的任何操作码后返回脚本。 如果操作码没有出现在脚本中，则原始脚本将不加修改地返回。 否则，将分配一个新脚本来包含过滤后的脚本。 此方法假设脚本解析成功。
//
// 注意：该函数仅对0版本脚本有效。 由于该函数不接受脚本版本，因此其他脚本版本的结果未定义。
func removeOpcodeRaw(script []byte, opcode byte) []byte {
	// Avoid work when possible.
	if len(script) == 0 {
		return script
	}

	const scriptVersion = 0
	var result []byte
	var prevOffset int32

	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		if tokenizer.Opcode() == opcode {
			if result == nil {
				result = make([]byte, 0, len(script))
				result = append(result, script[:prevOffset]...)
			}
		} else if result != nil {
			result = append(result, script[prevOffset:tokenizer.ByteIndex()]...)
		}
		prevOffset = tokenizer.ByteIndex()
	}
	if result == nil {
		return script
	}
	return result
}

// 如果操作码不是推送指令或者与推送指令关联的数据使用最小的指令来完成工作，则 isCanonicalPush 返回 true。 否则为假。
//
// 例如，可以将值 1 以"OP_1"、"OP_DATA_1 0x01"、"OP_PUSHDATA1 0x01 0x01"等形式压入堆栈，但是第一个只占用一个字节，其余的则占用一个字节 更多的。 只有第一个被认为是规范的。
func isCanonicalPush(opcode byte, data []byte) bool {
	dataLen := len(data)
	if opcode > OP_16 {
		return true
	}

	if opcode < OP_PUSHDATA1 && opcode > OP_0 && (dataLen == 1 && data[0] <= 16) {
		return false
	}
	if opcode == OP_PUSHDATA1 && dataLen < OP_PUSHDATA1 {
		return false
	}
	if opcode == OP_PUSHDATA2 && dataLen <= 0xff {
		return false
	}
	if opcode == OP_PUSHDATA4 && dataLen <= 0xffff {
		return false
	}
	return true
}

// removeOpcodeByData 将返回减去执行规范数据推送（包含要删除的传递数据）的任何操作码的脚本。 此函数假设提供了版本 0 脚本，因为任何未来版本的脚本都应避免此功能，因为由于签名脚本不是无见证交易哈希的一部分，因此它是不必要的。
//
// 警告：这将返回未修改的传递脚本，除非需要修改，在这种情况下将返回修改后的脚本。 这意味着调用者可能不依赖于能够安全地改变传递或返回的脚本而不可能修改相同的数据。
//
// 注意：该函数仅对0版本脚本有效。 由于该函数不接受脚本版本，因此其他脚本版本的结果未定义。
func removeOpcodeByData(script []byte, dataToRemove []byte) []byte {
	// Avoid work when possible.
	if len(script) == 0 || len(dataToRemove) == 0 {
		return script
	}

	// Parse through the script looking for a canonical data push that contains
	// the data to remove.
	const scriptVersion = 0
	var result []byte
	var prevOffset int32
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		// In practice, the script will basically never actually contain the
		// data since this function is only used during signature verification
		// to remove the signature itself which would require some incredibly
		// non-standard code to create.
		//
		// Thus, as an optimization, avoid allocating a new script unless there
		// is actually a match that needs to be removed.
		op, data := tokenizer.Opcode(), tokenizer.Data()
		if isCanonicalPush(op, data) && bytes.Contains(data, dataToRemove) {
			if result == nil {
				fullPushLen := tokenizer.ByteIndex() - prevOffset
				result = make([]byte, 0, int32(len(script))-fullPushLen)
				result = append(result, script[0:prevOffset]...)
			}
		} else if result != nil {
			result = append(result, script[prevOffset:tokenizer.ByteIndex()]...)
		}

		prevOffset = tokenizer.ByteIndex()
	}
	if result == nil {
		result = script
	}
	return result
}

// AsSmallInt 以整数形式返回传递的操作码，根据 IsSmallInt()，该操作码必须为 true。
func AsSmallInt(op byte) int {
	if op == OP_0 {
		return 0
	}

	return int(op - (OP_1 - 1))
}

// countSigOpsV0 返回所提供脚本中到第一次解析失败点为止的签名操作数，或者在没有解析失败时返回整个脚本。 精确标志尝试准确计算多重签名操作的操作次数与使用允许的最大值。
//
// 警告：此函数始终将传递的脚本视为版本 0。如果引入新的脚本版本，则必须非常小心，因为它是一致使用的，不幸的是，截至撰写本文时，在计数之前不会检查脚本版本
// 它们的签名操作意味着现有规则上的节点将计算新版本脚本，就好像它们是版本 0 一样。
func countSigOpsV0(script []byte, precise bool) int {
	const scriptVersion = 0

	numSigOps := 0
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	prevOp := byte(OP_INVALIDOPCODE)
	for tokenizer.Next() {
		switch tokenizer.Opcode() {
		case OP_CHECKSIG, OP_CHECKSIGVERIFY:
			numSigOps++

		case OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY:
			// Note that OP_0 is treated as the max number of sigops here in
			// precise mode despite it being a valid small integer in order to
			// highly discourage multisigs with zero pubkeys.
			//
			// Also, even though this is referred to as "precise" counting, it's
			// not really precise at all due to the small int opcodes only
			// covering 1 through 16 pubkeys, which means this will count any
			// more than that value (e.g. 17, 18 19) as the maximum number of
			// allowed pubkeys. This is, unfortunately, now part of
			// the Bitcoin consensus rules, due to historical
			// reasons. This could be made more correct with a new
			// script version, however, ideally all multisignaure
			// operations in new script versions should move to
			// aggregated schemes such as Schnorr instead.
			if precise && prevOp >= OP_1 && prevOp <= OP_16 {
				numSigOps += AsSmallInt(prevOp)
			} else {
				numSigOps += MaxPubKeysPerMultiSig
			}

		default:
			// Not a sigop.
		}

		prevOp = tokenizer.Opcode()
	}

	return numSigOps
}

// GetSigOpCount 提供脚本中签名操作数量的快速计数。 CHECKSIG 操作计数为 1，CHECK_MULTISIG 计数为 20。
// 如果脚本解析失败，则返回失败点之前的计数。
//
// 警告：此函数始终将传递的脚本视为版本 0。如果引入新的脚本版本，则必须非常小心，因为它是一致使用的，不幸的是，截至撰写本文时，在计数之前不会检查脚本版本
// 它们的签名操作意味着现有规则上的节点将计算新版本脚本，就好像它们是版本 0 一样。
func GetSigOpCount(script []byte) int {
	return countSigOpsV0(script, false)
}

// FinalOpcodeData 返回与脚本中最终操作码关联的数据。 如果脚本解析失败，它将返回 nil。
func finalOpcodeData(scriptVersion uint16, script []byte) []byte {
	// Avoid unnecessary work.
	if len(script) == 0 {
		return nil
	}

	var data []byte
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		data = tokenizer.Data()
	}
	if tokenizer.Err() != nil {
		return nil
	}
	return data
}

// GetPreciseSigOpCount 返回 scriptPubKey 中签名操作的数量。
// 如果 bip16 为 true，则可以搜索 scriptSig 来查找 Pay-To-Script-Hash 脚本，以便找到交易中签名操作的精确数量。
// 如果脚本解析失败，则返回失败点之前的计数。
//
// 警告：此函数始终将传递的脚本视为版本 0。
// 如果引入新的脚本版本，则必须非常小心，因为它是一致使用的，不幸的是，截至撰写本文时，在计数之前不会检查脚本版本
// 它们的签名操作意味着现有规则上的节点将计算新版本脚本，就好像它们是版本 0 一样。
//
// 第三个参数已弃用且未使用。
func GetPreciseSigOpCount(scriptSig, scriptPubKey []byte, _ bool) int {
	const scriptVersion = 0

	// Treat non P2SH transactions as normal.  Note that signature operation
	// counting includes all operations up to the first parse failure.
	if !isScriptHashScript(scriptPubKey) {
		return countSigOpsV0(scriptPubKey, true)
	}

	// The signature script must only push data to the stack for P2SH to be
	// a valid pair, so the signature operation count is 0 when that is not
	// the case.
	if len(scriptSig) == 0 || !IsPushOnlyScript(scriptSig) {
		return 0
	}

	// The P2SH script is the last item the signature script pushes to the
	// stack.  When the script is empty, there are no signature operations.
	//
	// Notice that signature scripts that fail to fully parse count as 0
	// signature operations unlike public key and redeem scripts.
	redeemScript := finalOpcodeData(scriptVersion, scriptSig)
	if len(redeemScript) == 0 {
		return 0
	}

	// Return the more precise sigops count for the redeem script.  Note that
	// signature operation counting includes all operations up to the first
	// parse failure.
	return countSigOpsV0(redeemScript, true)
}

// GetWitnessSigOpCount 返回通过使用指定见证人或 sigScript 传递的 pkScript 生成的签名操作数。
// 与GetPreciseSigOpCount不同的是，该函数能够准确统计花费见证程序以及嵌套的p2sh见证程序生成的签名操作的数量。 如果脚本解析失败，则返回失败点之前的计数。
func GetWitnessSigOpCount(sigScript, pkScript []byte, witness wire.TxWitness) int {
	// If this is a regular witness program, then we can proceed directly
	// to counting its signature operations without any further processing.
	if isWitnessProgramScript(pkScript) {
		return getWitnessSigOps(pkScript, witness)
	}

	// Next, we'll check the sigScript to see if this is a nested p2sh
	// witness program. This is a case wherein the sigScript is actually a
	// datapush of a p2wsh witness program.
	if isScriptHashScript(pkScript) && IsPushOnlyScript(sigScript) &&
		len(sigScript) > 0 && isWitnessProgramScript(sigScript[1:]) {
		return getWitnessSigOps(sigScript[1:], witness)
	}

	return 0
}

// getWitnessSigOps 返回通过使用通过的见证程序与通过的见证人生成的签名操作的数量。
// 确切的签名计数启发式由通过的见证程序的版本修改。
// 如果无法提取见证程序的版本，则 sig op 计数返回 0。
func getWitnessSigOps(pkScript []byte, witness wire.TxWitness) int {
	// Attempt to extract the witness program version.
	witnessVersion, witnessProgram, err := ExtractWitnessProgramInfo(
		pkScript,
	)
	if err != nil {
		return 0
	}

	switch witnessVersion {
	case BaseSegwitWitnessVersion:
		switch {
		case len(witnessProgram) == payToWitnessPubKeyHashDataSize:
			return 1
		case len(witnessProgram) == payToWitnessScriptHashDataSize &&
			len(witness) > 0:

			witnessScript := witness[len(witness)-1]
			return countSigOpsV0(witnessScript, true)
		}

	// Taproot signature operations don't count towards the block-wide sig
	// op limit, instead a distinct weight-based accounting method is used.
	case TaprootWitnessVersion:
		return 0
	}

	return 0
}

// 如果提供的脚本无法解析， checkScriptParses 将返回错误。
func checkScriptParses(scriptVersion uint16, script []byte) error {
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		// Nothing to do.
	}
	return tokenizer.Err()
}

// IsUnspendable 返回传递的公钥脚本是否不可花费，或者保证在执行时失败。 这允许在进入 UTXO 集时立即修剪输出。
//
// 注意：该函数仅对0版本脚本有效。 由于该函数不接受脚本版本，因此其他脚本版本的结果未定义。
func IsUnspendable(pkScript []byte) bool {
	// The script is unspendable if starts with OP_RETURN or is guaranteed
	// to fail at execution due to being larger than the max allowed script
	// size.
	switch {
	case len(pkScript) > 0 && pkScript[0] == OP_RETURN:
		return true
	case len(pkScript) > MaxScriptSize:
		return true
	}

	// The script is unspendable if it is guaranteed to fail at execution.
	const scriptVersion = 0
	return checkScriptParses(scriptVersion, pkScript) != nil
}

// 如果脚本中的任何操作码包含 OP_SUCCESS 操作码，则 ScriptHasOpSuccess 返回 true。
func ScriptHasOpSuccess(witnessScript []byte) bool {
	// First, create a new script tokenizer so we can run through all the
	// elements.
	tokenizer := MakeScriptTokenizer(0, witnessScript)

	// Run through all the op codes, returning true if we find anything
	// that is marked as a new op success.
	for tokenizer.Next() {
		if _, ok := successOpcodes[tokenizer.Opcode()]; ok {
			return true
		}
	}

	return false
}
