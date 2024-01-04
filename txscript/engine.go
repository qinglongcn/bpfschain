// 包含脚本执行引擎的核心代码，负责处理脚本的解析和执行。

package txscript

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/sirupsen/logrus"
)

// ScriptFlags 是一个位掩码，定义执行脚本对时将完成的附加操作或测试。
type ScriptFlags uint32

const (
	// ScriptBip16 定义是否已通过 bip16 阈值，因此支付脚本哈希交易将得到充分验证。
	ScriptBip16 ScriptFlags = 1 << iota

	// ScriptStrictMultiSig 定义是否验证 CHECKMULTISIG 使用的堆栈项长度为零。
	ScriptStrictMultiSig

	// ScriptDiscourageUpgradableNops 定义是否验证 NOP1 到 NOP10 是否保留用于将来的软分叉升级。
	// 该标志不得用于共识关键代码，也不得应用于区块，因为该标志仅用于更严格的标准交易检查。
	// 该标志仅在执行上述操作码时应用。
	ScriptDiscourageUpgradableNops

	// ScriptVerifyCheckLockTimeVerify 定义是否根据锁定时间验证交易输出是否可花费。
	// 这是 BIP0065。
	ScriptVerifyCheckLockTimeVerify

	// ScriptVerifyCheckSequenceVerify 定义是否允许根据输出的使用期限限制脚本的执行路径。
	// 这是 BIP0112。
	ScriptVerifyCheckSequenceVerify

	// ScriptVerifyCleanStack 定义堆栈在求值后必须仅包含一个堆栈元素，并且如果解释为布尔值，则该元素必须为 true。
	// 这是 BIP0062 的规则 6。
	// 如果没有 ScriptBip16 标志或 ScriptVerifyWitness 标志，则永远不应使用此标志。
	ScriptVerifyCleanStack

	// ScriptVerifyDERSignatures 定义签名需要符合 DER 格式。
	ScriptVerifyDERSignatures

	// ScriptVerifyLowS 定义签名需要符合DER格式，其S值<= order / 2。
	// 这是BIP0062的规则5。
	ScriptVerifyLowS

	// ScriptVerifyMinimalData 定义签名必须使用最小的推送运算符。
	// 这也是 BIP0062 的规则 3 和 4。
	ScriptVerifyMinimalData

	// ScriptVerifyNullFail 定义如果 CHECKSIG 或 CHECKMULTISIG 操作失败，签名必须为空。
	ScriptVerifyNullFail

	// ScriptVerifySigPushOnly 定义签名脚本必须仅包含推送的数据。
	// 这是 BIP0062 的规则 2。
	ScriptVerifySigPushOnly

	// ScriptVerifyStrictEncoding 定义签名脚本和公钥必须遵循严格的编码要求。
	ScriptVerifyStrictEncoding

	// ScriptVerifyWitness 定义是否使用见证程序模板来验证交易输出。
	ScriptVerifyWitness

	// ScriptVerifyDiscourageUpgradeableWitnessProgram 使版本 2-16 的见证程序成为非标准。
	ScriptVerifyDiscourageUpgradeableWitnessProgram

	// ScriptVerifyMinimalIf 使用 OP_IF/OP_NOTIF 制作脚本，其操作数不是空向量或 [0x01] 非标准。
	ScriptVerifyMinimalIf

	// ScriptVerifyWitnessPubKeyType 使 check-sig 操作中的脚本的公钥未以非标准压缩格式序列化。
	ScriptVerifyWitnessPubKeyType

	// ScriptVerifyTaproot 定义是否使用新的主根验证规则来验证交易输出。
	ScriptVerifyTaproot

	// ScriptVerifyDiscourageUpgradeableWitnessProgram 定义是否将任何新的/未知的主根叶子版本视为非标准。
	ScriptVerifyDiscourageUpgradeableTaprootVersion

	// ScriptVerifyDiscourageOpSuccess 定义是否在 Tapscript 执行期间将 OP_SUCCESS 操作码的使用视为非标准。
	ScriptVerifyDiscourageOpSuccess

	// ScriptVerifyDiscourageUpgradeablePubkeyType 定义未知的公钥版本（在 Tapscript 执行期间）是否是非标准的。
	ScriptVerifyDiscourageUpgradeablePubkeyType
)

const (
	// MaxStackSize 是执行期间堆栈和替代堆栈的最大组合高度。
	MaxStackSize = 1000

	// MaxScriptSize 是原始脚本允许的最大长度。
	MaxScriptSize = 10000

	// payToWitnessPubKeyHashDataSize 是见证程序针对付费见证公钥哈希输出的数据推送的大小。
	payToWitnessPubKeyHashDataSize = 20

	// payToWitnessScriptHashDataSize 是支付见证脚本哈希输出的见证程序数据推送的大小。
	payToWitnessScriptHashDataSize = 32

	// payToTaprootDataSize 是见证人计划推动主根支出的规模。
	// 这将是顶级主根输出公钥的序列化 x 坐标。
	payToTaprootDataSize = 32
)

const (
	// BaseSegwitWitnessVersion 是定义初始隔离见证验证逻辑集的原始见证版本。
	BaseSegwitWitnessVersion = 0

	// TaprootWitnessVersion 是定义新的主根验证逻辑的见证版本。
	TaprootWitnessVersion = 1
)

// halforder 用于驯服 ECDSA 的延展性（请参阅 BIP0062）。
var halfOrder = new(big.Int).Rsh(btcec.S256().N, 1)

// taprootExecutionCtx 包含我们验证主根脚本支出所需的特殊上下文特定信息。
// 这包括附件、运行的 sig op 计数以及其他相关信息。
type taprootExecutionCtx struct {
	annex []byte

	codeSepPos uint32

	tapLeafHash chainhash.Hash

	sigOpsBudget int32

	mustSucceed bool
}

// sigOpsDelta 既是用于 Tapscript 验证的 sig ops 的起始预算，也是我们遇到签名时总预算的减少。
const sigOpsDelta = 50

// tallysigOp 尝试将当前 sig ops 预算减少 sigOpsDelta。
// 如果减去增量后预算低于零，则返回错误。
func (t *taprootExecutionCtx) tallysigOp() error {
	t.sigOpsBudget -= sigOpsDelta

	if t.sigOpsBudget < 0 {
		return scriptError(ErrTaprootMaxSigOps, "")
	}

	return nil
}

// newTaprootExecutionCtx 返回主根执行上下文的新实例。
func newTaprootExecutionCtx(inputWitnessSize int32) *taprootExecutionCtx {
	return &taprootExecutionCtx{
		codeSepPos:   blankCodeSepValue,
		sigOpsBudget: sigOpsDelta + inputWitnessSize,
	}
}

// Engine 是执行脚本的虚拟机。
type Engine struct {
	// 以下字段在创建引擎时设置，之后不得更改。 签名缓存的条目在执行过程中会发生变化，但是缓存指针本身不会改变。
	//
	// flags 指定修改引擎执行行为的附加标志。
	//
	// tx 标识包含输入的交易，该输入又包含正在执行的签名脚本。
	//
	// txIdx 标识包含正在执行的签名脚本的交易中的输入索引。
	//
	// version 指定要执行的公钥脚本的版本。 由于签名脚本兑换公钥脚本，这意味着在支付脚本哈希的情况下，同一版本也扩展到签名脚本和兑换脚本。
	//
	// bip16 指定公钥脚本是一种特殊形式，表明它是 BIP16 pay-to-script-hash，因此必须如此对待执行。
	//
	// sigCache 缓存签名验证的结果。 这很有用，因为交易脚本通常会从各种上下文中多次执行（例如，新的块模板、在挖掘交易之前首次看到交易时、完整块验证的一部分等）。
	//
	// hashCache 缓存 segwit v0 和 v1 sighashes 的中间状态，以优化最坏情况下的哈希复杂性。
	//
	// prevOutFetcher 用于查找主根交易的所有先前输出，因为该信息被散列到此类输入的ighash 摘要中。
	flags          ScriptFlags
	tx             wire.MsgTx
	txIdx          int
	version        uint16
	bip16          bool
	sigCache       *SigCache
	hashCache      *TxSigHashes
	prevOutFetcher PrevOutputFetcher

	// 以下字段负责跟踪引擎的当前执行状态。
	//
	// 脚本存放由引擎执行的原始脚本。 这包括签名脚本和公钥脚本。 在支付脚本哈希的情况下，它还包括兑换脚本。
	//
	// scriptIdx 跟踪当前程序计数器的脚本数组中的索引。
	//
	// opcodeIdx 跟踪当前程序计数器的当前脚本中的操作码编号。 请注意，它与脚本中的实际字节索引不同，实际上仅用于反汇编目的。
	//
	//lastCodeSep 指定最后一个 OP_CODESEPARATOR 在当前脚本中的位置。
	//
	// tokenizer 提供当前正在执行的脚本的令牌流，并兼作脚本内程序计数器的状态跟踪。
	//
	// 在执行 pay-to-script-hash 执行时，savedFirstStack 保留第一个脚本的堆栈副本。
	//
	// dstack 是执行期间各种操作码推送和弹出数据的主要数据堆栈。
	//
	// astack 是备用数据堆栈，各种操作码在执行期间进出数据。
	//
	// condStack 跟踪条件执行状态，支持多个嵌套条件执行操作码。
	//
	// numOps 跟踪脚本中非推送操作的总数，主要用于强制执行最大限制。
	scripts         [][]byte
	scriptIdx       int
	opcodeIdx       int
	lastCodeSep     int
	tokenizer       ScriptTokenizer
	savedFirstStack [][]byte
	dstack          stack
	astack          stack
	condStack       []int
	numOps          int
	witnessVersion  int
	witnessProgram  []byte
	inputAmount     int64
	taprootCtx      *taprootExecutionCtx
}

// hasFlag 返回脚本引擎实例是否设置了传递的标志。
func (vm *Engine) hasFlag(flag ScriptFlags) bool {
	return vm.flags&flag == flag
}

// isBranchExecuting 返回当前条件分支是否正在主动执行。
// 例如，当数据堆栈上有 OP_FALSE 并且遇到 OP_IF 时，分支处于非活动状态，直到遇到 OP_ELSE 或 OP_ENDIF。 它正确处理嵌套条件。
func (vm *Engine) isBranchExecuting() bool {
	if len(vm.condStack) == 0 {
		return true
	}
	return vm.condStack[len(vm.condStack)-1] == OpCondTrue
}

// isOpcodeDisabled 返回操作码是否被禁用，因此在指令流中总是很难看到（即使被条件关闭）。
func isOpcodeDisabled(opcode byte) bool {
	switch opcode {
	case OP_CAT:
		return true
	case OP_SUBSTR:
		return true
	case OP_LEFT:
		return true
	case OP_RIGHT:
		return true
	case OP_INVERT:
		return true
	case OP_AND:
		return true
	case OP_OR:
		return true
	case OP_XOR:
		return true
	case OP_2MUL:
		return true
	case OP_2DIV:
		return true
	case OP_MUL:
		return true
	case OP_DIV:
		return true
	case OP_MOD:
		return true
	case OP_LSHIFT:
		return true
	case OP_RSHIFT:
		return true
	default:
		return false
	}
}

// isOpcodeAlwaysIllegal 返回操作码在被程序计数器传递时是否始终非法，即使在未执行的分支中也是如此（它们是条件语句并非巧合）。
func isOpcodeAlwaysIllegal(opcode byte) bool {
	switch opcode {
	case OP_VERIF:
		return true
	case OP_VERNOTIF:
		return true
	default:
		return false
	}
}

// isOpcodeConditional 返回操作码是否是条件操作码，该操作码在执行时会更改条件执行堆栈。
func isOpcodeConditional(opcode byte) bool {
	switch opcode {
	case OP_IF:
		return true
	case OP_NOTIF:
		return true
	case OP_ELSE:
		return true
	case OP_ENDIF:
		return true
	default:
		return false
	}
}

// checkMinimalDataPush 返回所提供的操作码是否是表示给定数据的最小可能方式。
// 例如，可以使用 OP_DATA_1 15（以及其他变体）推送值 15； 然而，OP_15 是表示相同值的单个操作码，并且只是一个字节而不是两个字节。
func checkMinimalDataPush(op *opcode, data []byte) error {
	opcodeVal := op.value
	dataLen := len(data)
	switch {
	case dataLen == 0 && opcodeVal != OP_0:
		str := fmt.Sprintf("zero length data push is encoded with opcode %s "+
			"instead of OP_0", op.name)
		return scriptError(ErrMinimalData, str)
	case dataLen == 1 && data[0] >= 1 && data[0] <= 16:
		if opcodeVal != OP_1+data[0]-1 {
			// Should have used OP_1 .. OP_16
			str := fmt.Sprintf("data push of the value %d encoded with opcode "+
				"%s instead of OP_%d", data[0], op.name, data[0])
			return scriptError(ErrMinimalData, str)
		}
	case dataLen == 1 && data[0] == 0x81:
		if opcodeVal != OP_1NEGATE {
			str := fmt.Sprintf("data push of the value -1 encoded with opcode "+
				"%s instead of OP_1NEGATE", op.name)
			return scriptError(ErrMinimalData, str)
		}
	case dataLen <= 75:
		if int(opcodeVal) != dataLen {
			// Should have used a direct push
			str := fmt.Sprintf("data push of %d bytes encoded with opcode %s "+
				"instead of OP_DATA_%d", dataLen, op.name, dataLen)
			return scriptError(ErrMinimalData, str)
		}
	case dataLen <= 255:
		if opcodeVal != OP_PUSHDATA1 {
			str := fmt.Sprintf("data push of %d bytes encoded with opcode %s "+
				"instead of OP_PUSHDATA1", dataLen, op.name)
			return scriptError(ErrMinimalData, str)
		}
	case dataLen <= 65535:
		if opcodeVal != OP_PUSHDATA2 {
			str := fmt.Sprintf("data push of %d bytes encoded with opcode %s "+
				"instead of OP_PUSHDATA2", dataLen, op.name)
			return scriptError(ErrMinimalData, str)
		}
	}
	return nil
}

// 执行操作码对传递的操作码执行执行。
// 它考虑到它是否被条件隐藏，但在这种情况下仍然必须测试一些规则。
func (vm *Engine) executeOpcode(op *opcode, data []byte) error {
	// Disabled opcodes are fail on program counter.
	if isOpcodeDisabled(op.value) {
		str := fmt.Sprintf("attempt to execute disabled opcode %s", op.name)
		return scriptError(ErrDisabledOpcode, str)
	}

	// Always-illegal opcodes are fail on program counter.
	if isOpcodeAlwaysIllegal(op.value) {
		str := fmt.Sprintf("attempt to execute reserved opcode %s", op.name)
		return scriptError(ErrReservedOpcode, str)
	}

	// Note that this includes OP_RESERVED which counts as a push operation.
	if vm.taprootCtx == nil && op.value > OP_16 {
		vm.numOps++
		if vm.numOps > MaxOpsPerScript {
			str := fmt.Sprintf("exceeded max operation limit of %d",
				MaxOpsPerScript)
			return scriptError(ErrTooManyOperations, str)
		}

	} else if len(data) > MaxScriptElementSize {
		str := fmt.Sprintf("element size %d exceeds max allowed size %d",
			len(data), MaxScriptElementSize)
		return scriptError(ErrElementTooBig, str)
	}

	// Nothing left to do when this is not a conditional opcode and it is
	// not in an executing branch.
	if !vm.isBranchExecuting() && !isOpcodeConditional(op.value) {
		return nil
	}

	// Ensure all executed data push opcodes use the minimal encoding when
	// the minimal data verification flag is set.
	if vm.dstack.verifyMinimalData && vm.isBranchExecuting() &&
		op.value >= 0 && op.value <= OP_PUSHDATA4 {

		if err := checkMinimalDataPush(op, data); err != nil {
			return err
		}
	}

	return op.opfunc(op, data, vm)
}

// 如果当前脚本位置对于执行无效，则 checkValidPC 返回错误。
func (vm *Engine) checkValidPC() error {
	if vm.scriptIdx >= len(vm.scripts) {
		str := fmt.Sprintf("script index %d beyond total scripts %d",
			vm.scriptIdx, len(vm.scripts))
		return scriptError(ErrInvalidProgramCounter, str)
	}
	return nil
}

// 如果在引擎初始化期间提取了见证程序，并且该程序的版本与指定版本匹配，则 isWitnessVersionActive 返回 true。
func (vm *Engine) isWitnessVersionActive(version uint) bool {
	return vm.witnessProgram != nil && uint(vm.witnessVersion) == version
}

// verifyWitnessProgram 使用传递的见证作为输入来验证存储的见证程序。
func (vm *Engine) verifyWitnessProgram(witness wire.TxWitness) error {
	switch {

	// We're attempting to verify a base (witness version 0) segwit output,
	// so we'll be looking for either a p2wsh or a p2wkh spend.
	case vm.isWitnessVersionActive(BaseSegwitWitnessVersion):
		switch len(vm.witnessProgram) {
		case payToWitnessPubKeyHashDataSize: // P2WKH
			// The witness stack should consist of exactly two
			// items: the signature, and the pubkey.
			if len(witness) != 2 {
				err := fmt.Sprintf("should have exactly two "+
					"items in witness, instead have %v", len(witness))
				return scriptError(ErrWitnessProgramMismatch, err)
			}

			// Now we'll resume execution as if it were a regular
			// p2pkh transaction.
			pkScript, err := payToPubKeyHashScript(vm.witnessProgram)
			if err != nil {
				return err
			}

			const scriptVersion = 0
			err = checkScriptParses(vm.version, pkScript)
			if err != nil {
				return err
			}

			// Set the stack to the provided witness stack, then
			// append the pkScript generated above as the next
			// script to execute.
			vm.scripts = append(vm.scripts, pkScript)
			vm.SetStack(witness)

		case payToWitnessScriptHashDataSize: // P2WSH
			// Additionally, The witness stack MUST NOT be empty at
			// this point.
			if len(witness) == 0 {
				return scriptError(ErrWitnessProgramEmpty, "witness "+
					"program empty passed empty witness")
			}

			// Obtain the witness script which should be the last
			// element in the passed stack. The size of the script
			// MUST NOT exceed the max script size.
			witnessScript := witness[len(witness)-1]
			if len(witnessScript) > MaxScriptSize {
				str := fmt.Sprintf("witnessScript size %d "+
					"is larger than max allowed size %d",
					len(witnessScript), MaxScriptSize)
				return scriptError(ErrScriptTooBig, str)
			}

			// Ensure that the serialized pkScript at the end of
			// the witness stack matches the witness program.
			witnessHash := sha256.Sum256(witnessScript)
			if !bytes.Equal(witnessHash[:], vm.witnessProgram) {
				return scriptError(ErrWitnessProgramMismatch,
					"witness program hash mismatch")
			}

			// With all the validity checks passed, assert that the
			// script parses without failure.
			const scriptVersion = 0
			err := checkScriptParses(vm.version, witnessScript)
			if err != nil {
				return err
			}

			// The hash matched successfully, so use the witness as
			// the stack, and set the witnessScript to be the next
			// script executed.
			vm.scripts = append(vm.scripts, witnessScript)
			vm.SetStack(witness[:len(witness)-1])

		default:
			errStr := fmt.Sprintf("length of witness program "+
				"must either be %v or %v bytes, instead is %v bytes",
				payToWitnessPubKeyHashDataSize,
				payToWitnessScriptHashDataSize,
				len(vm.witnessProgram))
			return scriptError(ErrWitnessProgramWrongLength, errStr)
		}

	// We're attempting to to verify a taproot input, and the witness
	// program data push is of the expected size, so we'll be looking for a
	// normal key-path spend, or a merkle proof for a tapscript with
	// execution afterwards.
	case vm.isWitnessVersionActive(TaprootWitnessVersion) &&
		len(vm.witnessProgram) == payToTaprootDataSize && !vm.bip16:

		// If taproot isn't currently active, then we'll return a
		// success here in place as we don't apply the new rules unless
		// the flag flips, as governed by the version bits deployment.
		if !vm.hasFlag(ScriptVerifyTaproot) {
			return nil
		}

		// If there're no stack elements at all, then this is an
		// invalid spend.
		if len(witness) == 0 {
			return scriptError(ErrWitnessProgramEmpty, "witness "+
				"program empty passed empty witness")
		}

		// At this point, we know taproot is active, so we'll populate
		// the taproot execution context.
		vm.taprootCtx = newTaprootExecutionCtx(
			int32(witness.SerializeSize()),
		)

		// If we can detect the annex, then drop that off the stack,
		// we'll only need it to compute the sighash later.
		if isAnnexedWitness(witness) {
			vm.taprootCtx.annex, _ = extractAnnex(witness)

			// Snip the annex off the end of the witness stack.
			witness = witness[:len(witness)-1]
		}

		// From here, we'll either be validating a normal key spend, or
		// a spend from the tap script leaf using a committed leaf.
		switch {
		// If there's only a single element left on the stack (the
		// signature), then we'll apply the normal top-level schnorr
		// signature verification.
		case len(witness) == 1:
			// As we only have a single element left (after maybe
			// removing the annex), we'll do normal taproot
			// keyspend validation.
			rawSig := witness[0]
			err := VerifyTaprootKeySpend(
				vm.witnessProgram, rawSig, &vm.tx, vm.txIdx,
				vm.prevOutFetcher, vm.hashCache, vm.sigCache,
			)
			if err != nil {
				// TODO(roasbeef): proper error
				return err
			}

			// TODO(roasbeef): or remove the other items from the stack?
			vm.taprootCtx.mustSucceed = true
			return nil

		// Otherwise, we need to attempt full tapscript leaf
		// verification in place.
		default:
			// First, attempt to parse the control block, if this
			// isn't formatted properly, then we'll end execution
			// right here.
			controlBlock, err := ParseControlBlock(
				witness[len(witness)-1],
			)
			if err != nil {
				return err
			}

			// Now that we know the control block is valid, we'll
			// verify the top-level taproot commitment, which
			// proves that the specified script was committed to in
			// the merkle tree.
			witnessScript := witness[len(witness)-2]
			err = VerifyTaprootLeafCommitment(
				controlBlock, vm.witnessProgram, witnessScript,
			)
			if err != nil {
				return err
			}

			// Now that we know the commitment is valid, we'll
			// check to see if OP_SUCCESS op codes are found in the
			// script. If so, then we'll return here early as we
			// skip proper validation.
			if ScriptHasOpSuccess(witnessScript) {
				// An op success op code has been found, however if
				// the policy flag forbidding them is active, then
				// we'll return an error.
				if vm.hasFlag(ScriptVerifyDiscourageOpSuccess) {
					errStr := fmt.Sprintf("script contains " +
						"OP_SUCCESS op code")
					return scriptError(ErrDiscourageOpSuccess, errStr)
				}

				// Otherwise, the script passes scott free.
				vm.taprootCtx.mustSucceed = true
				return nil
			}

			// Before we proceed with normal execution, check the
			// leaf version of the script, as if the policy flag is
			// active, then we should only allow the base leaf
			// version.
			if controlBlock.LeafVersion != BaseLeafVersion {
				switch {
				case vm.hasFlag(ScriptVerifyDiscourageUpgradeableTaprootVersion):
					errStr := fmt.Sprintf("tapscript is attempting "+
						"to use version: %v", controlBlock.LeafVersion)
					return scriptError(
						ErrDiscourageUpgradeableTaprootVersion, errStr,
					)
				default:
					// If the policy flag isn't active,
					// then execution succeeds here as we
					// don't know the rules of the future
					// leaf versions.
					vm.taprootCtx.mustSucceed = true
					return nil
				}
			}

			// Now that we know we don't have any op success
			// fields, ensure that the script parses properly.
			//
			// TODO(roasbeef): combine w/ the above?
			err = checkScriptParses(vm.version, witnessScript)
			if err != nil {
				return err
			}

			// Now that we know the script parses, and we have a
			// valid leaf version, we'll save the tapscript hash of
			// the leaf, as we need that for signature validation
			// later.
			vm.taprootCtx.tapLeafHash = NewBaseTapLeaf(
				witnessScript,
			).TapHash()

			// Otherwise, we'll now "recurse" one level deeper, and
			// set the remaining witness (leaving off the annex and
			// the witness script) as the execution stack, and
			// enter further execution.
			vm.scripts = append(vm.scripts, witnessScript)
			vm.SetStack(witness[:len(witness)-2])
		}

	case vm.hasFlag(ScriptVerifyDiscourageUpgradeableWitnessProgram):
		errStr := fmt.Sprintf("new witness program versions "+
			"invalid: %v", vm.witnessProgram)

		return scriptError(ErrDiscourageUpgradableWitnessProgram, errStr)
	default:
		// If we encounter an unknown witness program version and we
		// aren't discouraging future unknown witness based soft-forks,
		// then we de-activate the segwit behavior within the VM for
		// the remainder of execution.
		vm.witnessProgram = nil
	}

	// TODO(roasbeef): other sanity checks here
	switch {

	// In addition to the normal script element size limits, taproot also
	// enforces a limit on the max _starting_ stack size.
	case vm.isWitnessVersionActive(TaprootWitnessVersion):
		if vm.dstack.Depth() > MaxStackSize {
			str := fmt.Sprintf("tapscript stack size %d > max allowed %d",
				vm.dstack.Depth(), MaxStackSize)
			return scriptError(ErrStackOverflow, str)
		}

		fallthrough
	case vm.isWitnessVersionActive(BaseSegwitWitnessVersion):
		// All elements within the witness stack must not be greater
		// than the maximum bytes which are allowed to be pushed onto
		// the stack.
		for _, witElement := range vm.GetStack() {
			if len(witElement) > MaxScriptElementSize {
				str := fmt.Sprintf("element size %d exceeds "+
					"max allowed size %d", len(witElement),
					MaxScriptElementSize)
				return scriptError(ErrElementTooBig, str)
			}
		}

		return nil
	}

	return nil
}

// DisasmPC 返回用于反汇编操作码的字符串，该操作码将在调用 Step 时执行。
func (vm *Engine) DisasmPC() (string, error) {
	if err := vm.checkValidPC(); err != nil {
		return "", err
	}

	// Create a copy of the current tokenizer and parse the next opcode in the
	// copy to avoid mutating the current one.
	peekTokenizer := vm.tokenizer
	if !peekTokenizer.Next() {
		// Note that due to the fact that all scripts are checked for parse
		// failures before this code ever runs, there should never be an error
		// here, but check again to be safe in case a refactor breaks that
		// assumption or new script versions are introduced with different
		// semantics.
		if err := peekTokenizer.Err(); err != nil {
			return "", err
		}

		// Note that this should be impossible to hit in practice because the
		// only way it could happen would be for the final opcode of a script to
		// already be parsed without the script index having been updated, which
		// is not the case since stepping the script always increments the
		// script index when parsing and executing the final opcode of a script.
		//
		// However, check again to be safe in case a refactor breaks that
		// assumption or new script versions are introduced with different
		// semantics.
		str := fmt.Sprintf("program counter beyond script index %d (bytes %x)",
			vm.scriptIdx, vm.scripts[vm.scriptIdx])
		return "", scriptError(ErrInvalidProgramCounter, str)
	}

	var buf strings.Builder
	disasmOpcode(&buf, peekTokenizer.op, peekTokenizer.Data(), false)
	return fmt.Sprintf("%02x:%04x: %s", vm.scriptIdx, vm.opcodeIdx,
		buf.String()), nil
}

// DisasmScript 返回请求偏移索引处脚本的反汇编字符串。
// 索引0是签名脚本，1是公钥脚本。
// 在支付脚本哈希的情况下，一旦执行进度足以成功验证脚本哈希，索引 2 就是兑换脚本，从而将脚本添加到要执行的脚本中。
func (vm *Engine) DisasmScript(idx int) (string, error) {
	if idx >= len(vm.scripts) {
		str := fmt.Sprintf("script index %d >= total scripts %d", idx,
			len(vm.scripts))
		return "", scriptError(ErrInvalidIndex, str)
	}

	var disbuf strings.Builder
	script := vm.scripts[idx]
	tokenizer := MakeScriptTokenizer(vm.version, script)
	var opcodeIdx int
	for tokenizer.Next() {
		disbuf.WriteString(fmt.Sprintf("%02x:%04x: ", idx, opcodeIdx))
		disasmOpcode(&disbuf, tokenizer.op, tokenizer.Data(), false)
		disbuf.WriteByte('\n')
		opcodeIdx++
	}
	return disbuf.String(), tokenizer.Err()
}

// 如果运行的脚本已结束并成功，则 CheckErrorCondition 返回 nil，在堆栈上留下 true 布尔值。
// 否则会出现错误，包括脚本尚未完成的情况。
func (vm *Engine) CheckErrorCondition(finalScript bool) error {
	if vm.taprootCtx != nil && vm.taprootCtx.mustSucceed {
		return nil
	}

	// 检查执行实际上是通过确保脚本索引位于数组脚本中的最终脚本之后来完成的。
	if vm.scriptIdx < len(vm.scripts) {
		return scriptError(ErrScriptUnfinished,
			"error check when script unfinished")
	}

	// 如果我们处于版本零见证执行模式，并且这是最终脚本，那么堆栈必须是干净的，以便保持与 BIP16 的兼容性。
	if finalScript && vm.isWitnessVersionActive(BaseSegwitWitnessVersion) &&
		vm.dstack.Depth() != 1 {
		return scriptError(ErrEvalFalse, "witness program must "+
			"have clean stack")
	}

	// 当设置验证干净堆栈标志时，最终脚本必须以恰好一个数据堆栈项结束。
	// 否则，必须至少有一个数据堆栈项才能将其解释为布尔值。
	cleanStackActive := vm.hasFlag(ScriptVerifyCleanStack) || vm.taprootCtx != nil
	if finalScript && cleanStackActive && vm.dstack.Depth() != 1 {
		str := fmt.Sprintf("stack must contain exactly one item (contains %d)",
			vm.dstack.Depth())
		return scriptError(ErrCleanStack, str)
	} else if vm.dstack.Depth() < 1 {
		return scriptError(ErrEmptyStack,
			"stack empty at end of script execution")
	}

	v, err := vm.dstack.PopBool()
	if err != nil {
		return err
	}
	if !v {
		// 记录有趣的数据。
		logrus.Tracef("%v", newLogClosure(func() string {
			var buf strings.Builder
			buf.WriteString("scripts failed:\n")
			for i := range vm.scripts {
				dis, _ := vm.DisasmScript(i)
				buf.WriteString(fmt.Sprintf("script%d:\n", i))
				buf.WriteString(dis)
			}
			return buf.String()
		}))
		return scriptError(ErrEvalFalse,
			"false stack entry at end of script execution")
	}
	return nil
}

// Step 执行下一条指令，并将程序计数器移至脚本中的下一个操作码，如果当前已结束，则移至下一个脚本。
// 如果最后一个操作码成功执行，Step 将返回 true。
//
// 如果返回错误，则调用 Step 或任何其他方法的结果是未定义的。
func (vm *Engine) Step() (done bool, err error) {
	// Verify the engine is pointing to a valid program counter.
	if err := vm.checkValidPC(); err != nil {
		return true, err
	}

	// Attempt to parse the next opcode from the current script.
	if !vm.tokenizer.Next() {
		// Note that due to the fact that all scripts are checked for parse
		// failures before this code ever runs, there should never be an error
		// here, but check again to be safe in case a refactor breaks that
		// assumption or new script versions are introduced with different
		// semantics.
		if err := vm.tokenizer.Err(); err != nil {
			return false, err
		}

		str := fmt.Sprintf("attempt to step beyond script index %d (bytes %x)",
			vm.scriptIdx, vm.scripts[vm.scriptIdx])
		return true, scriptError(ErrInvalidProgramCounter, str)
	}

	// Execute the opcode while taking into account several things such as
	// disabled opcodes, illegal opcodes, maximum allowed operations per script,
	// maximum script element sizes, and conditionals.
	err = vm.executeOpcode(vm.tokenizer.op, vm.tokenizer.Data())
	if err != nil {
		return true, err
	}

	// The number of elements in the combination of the data and alt stacks
	// must not exceed the maximum number of stack elements allowed.
	combinedStackSize := vm.dstack.Depth() + vm.astack.Depth()
	if combinedStackSize > MaxStackSize {
		str := fmt.Sprintf("combined stack size %d > max allowed %d",
			combinedStackSize, MaxStackSize)
		return false, scriptError(ErrStackOverflow, str)
	}

	// Prepare for next instruction.
	vm.opcodeIdx++
	if vm.tokenizer.Done() {
		// Illegal to have a conditional that straddles two scripts.
		if len(vm.condStack) != 0 {
			return false, scriptError(ErrUnbalancedConditional,
				"end of script reached in conditional execution")
		}

		// Alt stack doesn't persist between scripts.
		_ = vm.astack.DropN(vm.astack.Depth())

		// The number of operations is per script.
		vm.numOps = 0

		// Reset the opcode index for the next script.
		vm.opcodeIdx = 0

		// Advance to the next script as needed.
		switch {
		case vm.scriptIdx == 0 && vm.bip16:
			vm.scriptIdx++
			vm.savedFirstStack = vm.GetStack()

		case vm.scriptIdx == 1 && vm.bip16:
			// Put us past the end for CheckErrorCondition()
			vm.scriptIdx++

			// Check script ran successfully.
			err := vm.CheckErrorCondition(false)
			if err != nil {
				return false, err
			}

			// Obtain the redeem script from the first stack and ensure it
			// parses.
			script := vm.savedFirstStack[len(vm.savedFirstStack)-1]
			if err := checkScriptParses(vm.version, script); err != nil {
				return false, err
			}
			vm.scripts = append(vm.scripts, script)

			// Set stack to be the stack from first script minus the redeem
			// script itself
			vm.SetStack(vm.savedFirstStack[:len(vm.savedFirstStack)-1])

		case vm.scriptIdx == 1 && vm.witnessProgram != nil,
			vm.scriptIdx == 2 && vm.witnessProgram != nil && vm.bip16: // np2sh

			vm.scriptIdx++

			witness := vm.tx.TxIn[vm.txIdx].Witness
			if err := vm.verifyWitnessProgram(witness); err != nil {
				return false, err
			}

		default:
			vm.scriptIdx++
		}

		// Skip empty scripts.
		if vm.scriptIdx < len(vm.scripts) && len(vm.scripts[vm.scriptIdx]) == 0 {
			vm.scriptIdx++
		}

		vm.lastCodeSep = 0
		if vm.scriptIdx >= len(vm.scripts) {
			return true, nil
		}

		// Finally, update the current tokenizer used to parse through scripts
		// one opcode at a time to start from the beginning of the new script
		// associated with the program counter.
		vm.tokenizer = MakeScriptTokenizer(vm.version, vm.scripts[vm.scriptIdx])
	}

	return false, nil
}

// 执行将执行脚本引擎中的所有脚本，如果验证成功则返回 nil，如果发生则返回错误。
func (vm *Engine) Execute() (err error) {
	// 目前除 0 之外的所有脚本版本都可以正常执行，从而使任何人都可以支付所有输出。
	// 将来这将允许添加新的脚本语言。
	if vm.version != 0 {
		return nil
	}

	done := false
	for !done {
		logrus.Tracef("%v", newLogClosure(func() string {
			dis, err := vm.DisasmPC()
			if err != nil {
				return fmt.Sprintf("stepping - failed to disasm pc: %v", err)
			}
			return fmt.Sprintf("stepping %v", dis)
		}))

		done, err = vm.Step()
		if err != nil {
			return err
		}
		logrus.Tracef("%v", newLogClosure(func() string {
			var dstr, astr string

			// 跟踪时记录非空堆栈。
			if vm.dstack.Depth() != 0 {
				dstr = "Stack:\n" + vm.dstack.String()
			}
			if vm.astack.Depth() != 0 {
				astr = "AltStack:\n" + vm.astack.String()
			}

			return dstr + astr
		}))
	}

	return vm.CheckErrorCondition(true)
}

// subScript 返回自最后一个 OP_CODESEPARATOR 以来的脚本。
func (vm *Engine) subScript() []byte {
	return vm.scripts[vm.scriptIdx][vm.lastCodeSep:]
}

// checkHashTypeEncoding 返回传递的哈希类型是否符合严格的编码要求（如果启用）。
func (vm *Engine) checkHashTypeEncoding(hashType SigHashType) error {
	if !vm.hasFlag(ScriptVerifyStrictEncoding) {
		return nil
	}

	sigHashType := hashType & ^SigHashAnyOneCanPay
	if sigHashType < SigHashAll || sigHashType > SigHashSingle {
		str := fmt.Sprintf("invalid hash type 0x%x", hashType)
		return scriptError(ErrInvalidSigHashType, str)
	}
	return nil
}

// isStrictPubKeyEncoding 返回传递的公钥是否符合严格的编码要求。
func isStrictPubKeyEncoding(pubKey []byte) bool {
	if len(pubKey) == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03) {
		// Compressed
		return true
	}
	if len(pubKey) == 65 {
		switch pubKey[0] {
		case 0x04:
			// Uncompressed
			return true

		case 0x06, 0x07:
			// Hybrid
			return true
		}
	}
	return false
}

// checkPubKeyEncoding 返回传递的公钥是否符合严格的编码要求（如果启用）。
func (vm *Engine) checkPubKeyEncoding(pubKey []byte) error {
	if vm.hasFlag(ScriptVerifyWitnessPubKeyType) &&
		vm.isWitnessVersionActive(BaseSegwitWitnessVersion) &&
		!btcec.IsCompressedPubKey(pubKey) {

		str := "only compressed keys are accepted post-segwit"
		return scriptError(ErrWitnessPubKeyType, str)
	}

	if !vm.hasFlag(ScriptVerifyStrictEncoding) {
		return nil
	}

	if len(pubKey) == 33 && (pubKey[0] == 0x02 || pubKey[0] == 0x03) {
		// Compressed
		return nil
	}
	if len(pubKey) == 65 && pubKey[0] == 0x04 {
		// Uncompressed
		return nil
	}

	return scriptError(ErrPubKeyType, "unsupported public key type")
}

// checkSignatureEncoding 返回传递的签名是否符合严格的编码要求（如果启用）。
func (vm *Engine) checkSignatureEncoding(sig []byte) error {
	if !vm.hasFlag(ScriptVerifyDERSignatures) &&
		!vm.hasFlag(ScriptVerifyLowS) &&
		!vm.hasFlag(ScriptVerifyStrictEncoding) {

		return nil
	}

	// The format of a DER encoded signature is as follows:
	//
	// 0x30 <total length> 0x02 <length of R> <R> 0x02 <length of S> <S>
	//   - 0x30 is the ASN.1 identifier for a sequence
	//   - Total length is 1 byte and specifies length of all remaining data
	//   - 0x02 is the ASN.1 identifier that specifies an integer follows
	//   - Length of R is 1 byte and specifies how many bytes R occupies
	//   - R is the arbitrary length big-endian encoded number which
	//     represents the R value of the signature.  DER encoding dictates
	//     that the value must be encoded using the minimum possible number
	//     of bytes.  This implies the first byte can only be null if the
	//     highest bit of the next byte is set in order to prevent it from
	//     being interpreted as a negative number.
	//   - 0x02 is once again the ASN.1 integer identifier
	//   - Length of S is 1 byte and specifies how many bytes S occupies
	//   - S is the arbitrary length big-endian encoded number which
	//     represents the S value of the signature.  The encoding rules are
	//     identical as those for R.
	const (
		asn1SequenceID = 0x30
		asn1IntegerID  = 0x02

		// minSigLen is the minimum length of a DER encoded signature and is
		// when both R and S are 1 byte each.
		//
		// 0x30 + <1-byte> + 0x02 + 0x01 + <byte> + 0x2 + 0x01 + <byte>
		minSigLen = 8

		// maxSigLen is the maximum length of a DER encoded signature and is
		// when both R and S are 33 bytes each.  It is 33 bytes because a
		// 256-bit integer requires 32 bytes and an additional leading null byte
		// might required if the high bit is set in the value.
		//
		// 0x30 + <1-byte> + 0x02 + 0x21 + <33 bytes> + 0x2 + 0x21 + <33 bytes>
		maxSigLen = 72

		// sequenceOffset is the byte offset within the signature of the
		// expected ASN.1 sequence identifier.
		sequenceOffset = 0

		// dataLenOffset is the byte offset within the signature of the expected
		// total length of all remaining data in the signature.
		dataLenOffset = 1

		// rTypeOffset is the byte offset within the signature of the ASN.1
		// identifier for R and is expected to indicate an ASN.1 integer.
		rTypeOffset = 2

		// rLenOffset is the byte offset within the signature of the length of
		// R.
		rLenOffset = 3

		// rOffset is the byte offset within the signature of R.
		rOffset = 4
	)

	// The signature must adhere to the minimum and maximum allowed length.
	sigLen := len(sig)
	if sigLen < minSigLen {
		str := fmt.Sprintf("malformed signature: too short: %d < %d", sigLen,
			minSigLen)
		return scriptError(ErrSigTooShort, str)
	}
	if sigLen > maxSigLen {
		str := fmt.Sprintf("malformed signature: too long: %d > %d", sigLen,
			maxSigLen)
		return scriptError(ErrSigTooLong, str)
	}

	// The signature must start with the ASN.1 sequence identifier.
	if sig[sequenceOffset] != asn1SequenceID {
		str := fmt.Sprintf("malformed signature: format has wrong type: %#x",
			sig[sequenceOffset])
		return scriptError(ErrSigInvalidSeqID, str)
	}

	// The signature must indicate the correct amount of data for all elements
	// related to R and S.
	if int(sig[dataLenOffset]) != sigLen-2 {
		str := fmt.Sprintf("malformed signature: bad length: %d != %d",
			sig[dataLenOffset], sigLen-2)
		return scriptError(ErrSigInvalidDataLen, str)
	}

	// Calculate the offsets of the elements related to S and ensure S is inside
	// the signature.
	//
	// rLen specifies the length of the big-endian encoded number which
	// represents the R value of the signature.
	//
	// sTypeOffset is the offset of the ASN.1 identifier for S and, like its R
	// counterpart, is expected to indicate an ASN.1 integer.
	//
	// sLenOffset and sOffset are the byte offsets within the signature of the
	// length of S and S itself, respectively.
	rLen := int(sig[rLenOffset])
	sTypeOffset := rOffset + rLen
	sLenOffset := sTypeOffset + 1
	if sTypeOffset >= sigLen {
		str := "malformed signature: S type indicator missing"
		return scriptError(ErrSigMissingSTypeID, str)
	}
	if sLenOffset >= sigLen {
		str := "malformed signature: S length missing"
		return scriptError(ErrSigMissingSLen, str)
	}

	// The lengths of R and S must match the overall length of the signature.
	//
	// sLen specifies the length of the big-endian encoded number which
	// represents the S value of the signature.
	sOffset := sLenOffset + 1
	sLen := int(sig[sLenOffset])
	if sOffset+sLen != sigLen {
		str := "malformed signature: invalid S length"
		return scriptError(ErrSigInvalidSLen, str)
	}

	// R elements must be ASN.1 integers.
	if sig[rTypeOffset] != asn1IntegerID {
		str := fmt.Sprintf("malformed signature: R integer marker: %#x != %#x",
			sig[rTypeOffset], asn1IntegerID)
		return scriptError(ErrSigInvalidRIntID, str)
	}

	// Zero-length integers are not allowed for R.
	if rLen == 0 {
		str := "malformed signature: R length is zero"
		return scriptError(ErrSigZeroRLen, str)
	}

	// R must not be negative.
	if sig[rOffset]&0x80 != 0 {
		str := "malformed signature: R is negative"
		return scriptError(ErrSigNegativeR, str)
	}

	// Null bytes at the start of R are not allowed, unless R would otherwise be
	// interpreted as a negative number.
	if rLen > 1 && sig[rOffset] == 0x00 && sig[rOffset+1]&0x80 == 0 {
		str := "malformed signature: R value has too much padding"
		return scriptError(ErrSigTooMuchRPadding, str)
	}

	// S elements must be ASN.1 integers.
	if sig[sTypeOffset] != asn1IntegerID {
		str := fmt.Sprintf("malformed signature: S integer marker: %#x != %#x",
			sig[sTypeOffset], asn1IntegerID)
		return scriptError(ErrSigInvalidSIntID, str)
	}

	// Zero-length integers are not allowed for S.
	if sLen == 0 {
		str := "malformed signature: S length is zero"
		return scriptError(ErrSigZeroSLen, str)
	}

	// S must not be negative.
	if sig[sOffset]&0x80 != 0 {
		str := "malformed signature: S is negative"
		return scriptError(ErrSigNegativeS, str)
	}

	// Null bytes at the start of S are not allowed, unless S would otherwise be
	// interpreted as a negative number.
	if sLen > 1 && sig[sOffset] == 0x00 && sig[sOffset+1]&0x80 == 0 {
		str := "malformed signature: S value has too much padding"
		return scriptError(ErrSigTooMuchSPadding, str)
	}

	// Verify the S value is <= half the order of the curve.  This check is done
	// because when it is higher, the complement modulo the order can be used
	// instead which is a shorter encoding by 1 byte.  Further, without
	// enforcing this, it is possible to replace a signature in a valid
	// transaction with the complement while still being a valid signature that
	// verifies.  This would result in changing the transaction hash and thus is
	// a source of malleability.
	if vm.hasFlag(ScriptVerifyLowS) {
		sValue := new(big.Int).SetBytes(sig[sOffset : sOffset+sLen])
		if sValue.Cmp(halfOrder) > 0 {
			return scriptError(ErrSigHighS, "signature is not canonical due "+
				"to unnecessarily high S value")
		}
	}

	return nil
}

// getStack 以自下而上的字节数组形式返回堆栈的内容
func getStack(stack *stack) [][]byte {
	array := make([][]byte, stack.Depth())
	for i := range array {
		// PeekByteArry can't fail due to overflow, already checked
		array[len(array)-i-1], _ = stack.PeekByteArray(int32(i))
	}
	return array
}

// setStack 将堆栈设置为数组的内容，其中数组中的最后一项是堆栈中的顶部项。
func setStack(stack *stack, data [][]byte) {
	// This can not error. Only errors are for invalid arguments.
	_ = stack.DropN(stack.Depth())

	for i := range data {
		stack.PushByteArray(data[i])
	}
}

// GetStack 以数组形式返回主堆栈的内容。 其中数组中的最后一项是堆栈的顶部。
func (vm *Engine) GetStack() [][]byte {
	return getStack(&vm.dstack)
}

// SetStack 将主堆栈的内容设置为所提供数组的内容，其中数组中的最后一项将是堆栈的顶部。
func (vm *Engine) SetStack(data [][]byte) {
	setStack(&vm.dstack, data)
}

// GetAltStack 以数组形式返回备用堆栈的内容，其中数组中的最后一项是堆栈的顶部。
func (vm *Engine) GetAltStack() [][]byte {
	return getStack(&vm.astack)
}

// SetAltStack 将备用堆栈的内容设置为所提供数组的内容，其中数组中的最后一项将是堆栈的顶部。
func (vm *Engine) SetAltStack(data [][]byte) {
	setStack(&vm.astack, data)
}

// NewEngine 为提供的公钥脚本、交易和输入索引返回一个新的脚本引擎。 标志根据每个标志提供的描述修改脚本引擎的行为。
func NewEngine(scriptPubKey []byte, tx *wire.MsgTx, txIdx int, flags ScriptFlags,
	sigCache *SigCache, hashCache *TxSigHashes, inputAmount int64,
	prevOutFetcher PrevOutputFetcher) (*Engine, error) {

	const scriptVersion = 0

	// 提供的交易输入索引必须引用有效的输入。
	if txIdx < 0 || txIdx >= len(tx.TxIn) {
		str := fmt.Sprintf("transaction input index %d is negative or "+
			">= %d", txIdx, len(tx.TxIn))
		return nil, scriptError(ErrInvalidIndex, str)
	}
	scriptSig := tx.TxIn[txIdx].SignatureScript

	// 当签名脚本和公钥脚本都为空时，结果必然是错误，因为堆栈最终会为空，这相当于错误的顶部元素。
	// 因此，现在只需返回相关错误作为优化即可。
	if len(scriptSig) == 0 && len(scriptPubKey) == 0 {
		return nil, scriptError(ErrEvalFalse,
			"false stack entry at end of script execution")
	}

	// 如果没有支付脚本哈希 (P2SH) 评估 (ScriptBip16) 标志或隔离见证 (ScriptVerifyWitness) 标志，则不允许使用干净堆栈标志 (ScriptVerifyCleanStack)。
	//
	// 回想一下，在没有设置标志的情况下评估 P2SH 脚本会导致非 P2SH 评估，从而将 P2SH 输入留在堆栈上。
	// 因此，允许干净堆栈标志而不使用 P2SH 标志将可能出现 P2SH 不应该是软分叉的情况。
	// 隔离见证也是如此，它将从见证堆栈中提取额外的脚本来执行。
	vm := Engine{
		flags:          flags,
		sigCache:       sigCache,
		hashCache:      hashCache,
		inputAmount:    inputAmount,
		prevOutFetcher: prevOutFetcher,
	}
	if vm.hasFlag(ScriptVerifyCleanStack) && (!vm.hasFlag(ScriptBip16) &&
		!vm.hasFlag(ScriptVerifyWitness)) {
		return nil, scriptError(ErrInvalidFlags,
			"invalid flags combination")
	}

	// 当设置了关联标志时，签名脚本必须仅包含数据推送。
	if vm.hasFlag(ScriptVerifySigPushOnly) && !IsPushOnlyScript(scriptSig) {
		return nil, scriptError(ErrNotPushOnly,
			"signature script is not push only")
	}

	// 签名脚本必须只包含PS2H的数据推送，这是根据公钥脚本的形式确定的。
	if vm.hasFlag(ScriptBip16) && isScriptHashScript(scriptPubKey) {
		// 仅接受为 P2SH 推送数据的输入脚本。
		// 请注意，当上面设置了验证签名脚本仅推送的标志时，仅推送检查已经完成，因此避免再次检查。
		alreadyChecked := vm.hasFlag(ScriptVerifySigPushOnly)
		if !alreadyChecked && !IsPushOnlyScript(scriptSig) {
			return nil, scriptError(ErrNotPushOnly,
				"pay to script hash is not push only")
		}
		vm.bip16 = true
	}

	// 引擎使用切片来存储脚本。 这允许按顺序执行多个脚本。 例如，对于支付脚本哈希交易，最终将需要执行第三个脚本。
	scripts := [][]byte{scriptSig, scriptPubKey}
	for _, scr := range scripts {
		if len(scr) > MaxScriptSize {
			str := fmt.Sprintf("script size %d is larger than max allowed "+
				"size %d", len(scr), MaxScriptSize)
			return nil, scriptError(ErrScriptTooBig, str)
		}

		const scriptVersion = 0
		if err := checkScriptParses(scriptVersion, scr); err != nil {
			return nil, err
		}
	}
	vm.scripts = scripts

	// 如果签名脚本为空，则将程序计数器推进到公钥脚本，因为在这种情况下没有任何可执行操作。
	if len(scriptSig) == 0 {
		vm.scriptIdx++
	}
	if vm.hasFlag(ScriptVerifyMinimalData) {
		vm.dstack.verifyMinimalData = true
		vm.astack.verifyMinimalData = true
	}

	// 检查我们是否应该根据设置的标志在见证验证模式下执行。
	// 我们在这里检查 pkScript 和 sigScript，因为在嵌套 p2sh 的情况下，scriptSig 将是有效的见证程序。
	// 对于嵌套 p2sh，第一次数据推送后的所有字节应“完全”匹配见证程序模板。
	if vm.hasFlag(ScriptVerifyWitness) {
		// 如果启用了见证评估，则 P2SH 也必须处于活动状态。
		if !vm.hasFlag(ScriptBip16) {
			errStr := "P2SH must be enabled to do witness verification"
			return nil, scriptError(ErrInvalidFlags, errStr)
		}

		var witProgram []byte

		switch {
		case IsWitnessProgram(vm.scripts[1]):
			// 对于所有本机见证程序来说，scriptSig 必须为*空*，否则我们会引入延展性。
			if len(scriptSig) != 0 {
				errStr := "native witness program cannot " +
					"also have a signature script"
				return nil, scriptError(ErrWitnessMalleated, errStr)
			}

			witProgram = scriptPubKey
		case len(tx.TxIn[txIdx].Witness) != 0 && vm.bip16:
			// sigScript 必须“准确”是见证程序的单个规范数据推送，否则我们将重新引入可延展性。
			sigPops := vm.scripts[0]
			if len(sigPops) > 2 &&
				isCanonicalPush(sigPops[0], sigPops[1:]) &&
				IsWitnessProgram(sigPops[1:]) {

				witProgram = sigPops[1:]
			} else {
				errStr := "signature script for witness " +
					"nested p2sh is not canonical"
				return nil, scriptError(ErrWitnessMalleatedP2SH, errStr)
			}
		}

		if witProgram != nil {
			var err error
			vm.witnessVersion, vm.witnessProgram, err = ExtractWitnessProgramInfo(
				witProgram,
			)
			if err != nil {
				return nil, err
			}
		} else {
			// 如果我们在 pkScript 中或 sigScript 中没有找到见证程序或作为数据推送，则不得有任何与正在验证的输入关联的见证数据。
			if vm.witnessProgram == nil && len(tx.TxIn[txIdx].Witness) != 0 {
				errStr := "non-witness inputs cannot have a witness"
				return nil, scriptError(ErrWitnessUnexpected, errStr)
			}
		}

	}

	// 设置当前分词器，用于通过与程序计数器关联的脚本一次解析一个操作码。
	vm.tokenizer = MakeScriptTokenizer(scriptVersion, scripts[vm.scriptIdx])

	vm.tx = *tx
	vm.txIdx = txIdx

	return &vm, nil
}
