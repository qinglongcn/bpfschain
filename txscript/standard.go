// 包含识别和处理标准交易类型的函数。

package txscript

import (
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

const (
	// MaxDataCarrierSize 是推送数据中允许的最大字节数。的最大字节数。
	MaxDataCarrierSize = 80

	//  StandardVerifyFlags 是脚本标志，在执行事务脚本时使用。
	//  执行交易脚本时使用的脚本标志，用于执行脚本被视为标准脚本所需的额外检查。
	//  这些检查有助于减少与交易可篡改性相关的问题，并允许付费脚本哈希交易。
	//  请注意，这些标志与共识规则的要求不同，它们更为严格。
	//  TODO: 这个定义不属于这里。 它属于策略 包中。
	StandardVerifyFlags = ScriptBip16 |
		ScriptVerifyDERSignatures |
		ScriptVerifyStrictEncoding |
		ScriptVerifyMinimalData |
		ScriptStrictMultiSig |
		ScriptDiscourageUpgradableNops |
		ScriptVerifyCleanStack |
		ScriptVerifyNullFail |
		ScriptVerifyCheckLockTimeVerify |
		ScriptVerifyCheckSequenceVerify |
		ScriptVerifyLowS |
		ScriptStrictMultiSig |
		ScriptVerifyWitness |
		ScriptVerifyDiscourageUpgradeableWitnessProgram |
		ScriptVerifyMinimalIf |
		ScriptVerifyWitnessPubKeyType |
		ScriptVerifyTaproot |
		ScriptVerifyDiscourageUpgradeableTaprootVersion |
		ScriptVerifyDiscourageOpSuccess |
		ScriptVerifyDiscourageUpgradeablePubkeyType
)

// ScriptClass 是脚本标准类型列表的枚举。
type ScriptClass byte

// 区块链中已知的脚本支付类别。
const (
	NonStandardTy         ScriptClass = iota // 没有任何公认的形式。
	PubKeyTy                                 // 支付 pubkey。
	PubKeyHashTy                             // 支付公用密钥哈希值。
	WitnessV0PubKeyHashTy                    // 支付见证人的公开密钥哈希值。
	ScriptHashTy                             // 为哈希脚本付费。
	WitnessV0ScriptHashTy                    // 付费见证脚本哈希。
	MultiSigTy                               // 多种签名。
	NullDataTy                               // 只有空数据（可证明可剪枝）。
	WitnessV1TaprootTy                       // 分根输出
	WitnessUnknownTy                         // 证人不详
)

// scriptClassToName 包含描述每个 脚本类的字符串。
var scriptClassToName = []string{
	NonStandardTy:         "nonstandard",
	PubKeyTy:              "pubkey",
	PubKeyHashTy:          "pubkeyhash",
	WitnessV0PubKeyHashTy: "witness_v0_keyhash",
	ScriptHashTy:          "scripthash",
	WitnessV0ScriptHashTy: "witness_v0_scripthash",
	MultiSigTy:            "multisig",
	NullDataTy:            "nulldata",
	WitnessV1TaprootTy:    "witness_v1_taproot",
	WitnessUnknownTy:      "witness_unknown",
}

// String 通过返回枚举脚本类的名称来实现 Stringer 接口。如果枚举无效，则返回 "Invalid"（无效）。
func (t ScriptClass) String() string {
	if int(t) > len(scriptClassToName) || int(t) < 0 {
		return "Invalid"
	}
	return scriptClassToName[t]
}

// extractCompressedPubKey 从传递的脚本中提取压缩公钥。脚本中提取压缩公钥。 否则将返回 nil。
func extractCompressedPubKey(script []byte) []byte {
	// A pay-to-compressed-pubkey script is of the form:
	//  OP_DATA_33 <33-byte compressed pubkey> OP_CHECKSIG

	// All compressed secp256k1 public keys must start with 0x02 or 0x03.
	if len(script) == 35 &&
		script[34] == OP_CHECKSIG &&
		script[0] == OP_DATA_33 &&
		(script[1] == 0x02 || script[1] == 0x03) {

		return script[1:34]
	}

	return nil
}

// extractUncompressedPubKey 从传递的脚本中提取未压缩的公钥。脚本中提取未压缩的公钥。 否则将返回 nil。
func extractUncompressedPubKey(script []byte) []byte {
	// A pay-to-uncompressed-pubkey script is of the form:
	//   OP_DATA_65 <65-byte uncompressed pubkey> OP_CHECKSIG
	//
	// All non-hybrid uncompressed secp256k1 public keys must start with 0x04.
	// Hybrid uncompressed secp256k1 public keys start with 0x06 or 0x07:
	//   - 0x06 => hybrid format for even Y coords
	//   - 0x07 => hybrid format for odd Y coords
	if len(script) == 67 &&
		script[66] == OP_CHECKSIG &&
		script[0] == OP_DATA_65 &&
		(script[1] == 0x04 || script[1] == 0x06 || script[1] == 0x07) {

		return script[1:66]
	}
	return nil
}

// extractPubKey 会从传递的脚本中提取压缩或未压缩的公钥，
// 前提是该脚本是标准的付费压缩-secp256k1-pubkey
// 脚本或付费未压缩-secp256k1-pubkey 脚本。 否则将返回 nil。
func extractPubKey(script []byte) []byte {
	if pubKey := extractCompressedPubKey(script); pubKey != nil {
		return pubKey
	}
	return extractUncompressedPubKey(script)
}

// isPubKeyScript 返回传递的脚本是否是标准的付费压缩-secp256k1-pubkey 或付费非压缩-secp256k1-pubkey 脚本。
func isPubKeyScript(script []byte) bool {
	return extractPubKey(script) != nil
}

// extractPubKeyHash 从传递的脚本中提取公钥哈希值，如果它 是标准的支付到公钥哈希脚本。 否则将返回 nil。
func extractPubKeyHash(script []byte) []byte {
	// A pay-to-pubkey-hash script is of the form:
	//  OP_DUP OP_HASH160 <20-byte hash> OP_EQUALVERIFY OP_CHECKSIG

	fmt.Printf("\nscript:\t\t%d\n", len(script))
	fmt.Printf("script[3:23]:\t%x\n", script[3:23])
	fmt.Printf("script[24]:\t%d\n\n", script[24])
	if len(script) == 25 &&
		script[0] == OP_DUP &&
		script[1] == OP_HASH160 &&
		script[2] == OP_DATA_20 &&
		script[23] == OP_EQUALVERIFY &&
		script[24] == OP_CHECKSIG {

		return script[3:23]
	}

	return nil
}

// isPubKeyHashScript 返回传递的脚本是否是标准的 支付到公钥哈希脚本。
func isPubKeyHashScript(script []byte) bool {
	return extractPubKeyHash(script) != nil
}

// extractScriptHash 会从传入的脚本中提取脚本哈希值（如果它是标准的付费到脚本哈希值脚本）。 否则将返回 nil。
//
// 注意：此函数仅对版本 0 的操作码有效。 由于该函数不接受脚本版本，因此对于其他版本的脚本，其结果是未定义的。
func extractScriptHash(script []byte) []byte {
	// A pay-to-script-hash script is of the form:
	//  OP_HASH160 <20-byte scripthash> OP_EQUAL
	if len(script) == 23 &&
		script[0] == OP_HASH160 &&
		script[1] == OP_DATA_20 &&
		script[22] == OP_EQUAL {

		return script[2:22]
	}

	return nil
}

// isScriptHashScript 返回传递的脚本是否是标准的 付费到脚本哈希脚本。
func isScriptHashScript(script []byte) bool {
	return extractScriptHash(script) != nil
}

// multiSigDetails 包含从标准多重签名脚本中提取的详细信息。
type multiSigDetails struct {
	requiredSigs int
	numPubKeys   int
	pubKeys      [][]byte
	valid        bool
}

// extractMultisigScriptDetails 会尝试从传递的脚本中提取详细信息。脚本中提取详细信息。 否则，返回的详细信息结构将把有效标志设为 false。
// 提取公钥标志表示是否也要提取公钥本身。
// 提供该标志的原因是，提取公钥会导致调用者可能希望的分配。
// 调用者可能希望避免分配。 当标记为 false 时，返回的详细信息结构中的 pubKeys 成员将为 nil。
// 注意：此函数仅对版本 0 的脚本有效。 对于其他版本的脚本，返回的详细信息结构将始终为空，且有效标志设置为 false。
func extractMultisigScriptDetails(scriptVersion uint16, script []byte, extractPubKeys bool) multiSigDetails {
	// The only currently supported script version is 0.
	if scriptVersion != 0 {
		return multiSigDetails{}
	}

	// A multi-signature script is of the form:
	//  NUM_SIGS PUBKEY PUBKEY PUBKEY ... NUM_PUBKEYS OP_CHECKMULTISIG

	// The script can't possibly be a multisig script if it doesn't end with
	// OP_CHECKMULTISIG or have at least two small integer pushes preceding it.
	// Fail fast to avoid more work below.
	if len(script) < 3 || script[len(script)-1] != OP_CHECKMULTISIG {
		return multiSigDetails{}
	}

	// The first opcode must be a small integer specifying the number of
	// signatures required.
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	if !tokenizer.Next() || !IsSmallInt(tokenizer.Opcode()) {
		return multiSigDetails{}
	}
	requiredSigs := AsSmallInt(tokenizer.Opcode())

	// The next series of opcodes must either push public keys or be a small
	// integer specifying the number of public keys.
	var numPubKeys int
	var pubKeys [][]byte
	if extractPubKeys {
		pubKeys = make([][]byte, 0, MaxPubKeysPerMultiSig)
	}
	for tokenizer.Next() {
		if IsSmallInt(tokenizer.Opcode()) {
			break
		}

		data := tokenizer.Data()
		numPubKeys++
		if !isStrictPubKeyEncoding(data) {
			continue
		}
		if extractPubKeys {
			pubKeys = append(pubKeys, data)
		}
	}
	if tokenizer.Done() {
		return multiSigDetails{}
	}

	// The next opcode must be a small integer specifying the number of public
	// keys required.
	op := tokenizer.Opcode()
	if !IsSmallInt(op) || AsSmallInt(op) != numPubKeys {
		return multiSigDetails{}
	}

	// There must only be a single opcode left unparsed which will be
	// OP_CHECKMULTISIG per the check above.
	if int32(len(tokenizer.Script()))-tokenizer.ByteIndex() != 1 {
		return multiSigDetails{}
	}

	return multiSigDetails{
		requiredSigs: requiredSigs,
		numPubKeys:   numPubKeys,
		pubKeys:      pubKeys,
		valid:        true,
	}
}

// isMultisigScript 返回传递的脚本是否是标准的多字符脚本。
//
// 注意：此函数仅对版本 0 的脚本有效。 对于其他版本的脚本，它总是返回 false。
func isMultisigScript(scriptVersion uint16, script []byte) bool {
	// Since this is only checking the form of the script, don't extract the
	// public keys to avoid the allocation.
	details := extractMultisigScriptDetails(scriptVersion, script, false)
	return details.valid
}

// IsMultisigScript 返回传递的脚本是否为标准多重签名脚本。
//
// 注意：此函数仅对版本 0 的脚本有效。 由于该函数不接受脚本版本，因此对于其他版本的脚本，其结果是未定义的。
//
// 该错误已被删除，并将在主要版本更新时移除。
func IsMultisigScript(script []byte) (bool, error) {
	const scriptVersion = 0
	return isMultisigScript(scriptVersion, script), nil
}

// IsMultisigSigScript 返回所传递的脚本是否是由支付到脚本-哈希多重签名赎回脚本组成的签名脚本。
// 要确定一个签名脚本实际上是否是支付到脚本-哈希赎回脚本，需要相关的公钥脚本，而获取公钥脚本的成本通常很高。
//
//	因此，通过检查签名脚本是否以数据推送结束，并将该数据推送视为 p2sh 赎回脚本，可以快速做出正确概率较高的尽力猜测。
//
// 注意：此函数仅对版本 0 的脚本有效。 由于该函数不接受脚本版本，因此对于其他版本的脚本，结果是未定义的。
func IsMultisigSigScript(script []byte) bool {
	const scriptVersion = 0

	// The script can't possibly be a multisig signature script if it doesn't
	// end with OP_CHECKMULTISIG in the redeem script or have at least two small
	// integers preceding it, and the redeem script itself must be preceded by
	// at least a data push opcode.  Fail fast to avoid more work below.
	if len(script) < 4 || script[len(script)-1] != OP_CHECKMULTISIG {
		return false
	}

	// Parse through the script to find the last opcode and any data it might
	// push and treat it as a p2sh redeem script even though it might not
	// actually be one.
	possibleRedeemScript := finalOpcodeData(scriptVersion, script)
	if possibleRedeemScript == nil {
		return false
	}

	// Finally, return if that possible redeem script is a multisig script.
	return isMultisigScript(scriptVersion, possibleRedeemScript)
}

// extractWitnessPubKeyHash 从传递的脚本中提取证人公钥哈希值（如果它是一个标准的付费-证人-公钥-哈希脚本）。否则将返回 否则将返回
func extractWitnessPubKeyHash(script []byte) []byte {
	// A pay-to-witness-pubkey-hash script is of the form:
	//   OP_0 OP_DATA_20 <20-byte-hash>
	if len(script) == witnessV0PubKeyHashLen &&
		script[0] == OP_0 &&
		script[1] == OP_DATA_20 {

		return script[2:witnessV0PubKeyHashLen]
	}

	return nil
}

// isWitnessPubKeyHashScript 返回传递的脚本是否为 是否是标准的支付-见证-公钥-散列脚本。
func isWitnessPubKeyHashScript(script []byte) bool {
	return extractWitnessPubKeyHash(script) != nil
}

// extractWitnessV0ScriptHash 从传递的脚本中提取证人脚本哈希值（如果该脚本是标准的付费-证人-脚本-哈希值脚本）。否则将返回零。
func extractWitnessV0ScriptHash(script []byte) []byte {
	// A pay-to-witness-script-hash script is of the form:
	//   OP_0 OP_DATA_32 <32-byte-hash>
	if len(script) == witnessV0ScriptHashLen &&
		script[0] == OP_0 &&
		script[1] == OP_DATA_32 {

		return script[2:34]
	}

	return nil
}

// extractWitnessV1KeyBytes 会提取原始公钥字节脚本（如果它是标准的付费-见证-脚本-散列 v1 脚本）。 否则将返回零。
func extractWitnessV1KeyBytes(script []byte) []byte {
	// A pay-to-witness-script-hash script is of the form:
	//   OP_1 OP_DATA_32 <32-byte-hash>
	if len(script) == witnessV1TaprootLen &&
		script[0] == OP_1 &&
		script[1] == OP_DATA_32 {

		return script[2:34]
	}

	return nil
}

// isWitnessScriptHashScript 返回传递的脚本是否为 标准的付费见证脚本哈希脚本。
func isWitnessScriptHashScript(script []byte) bool {
	return extractWitnessV0ScriptHash(script) != nil
}

// extractWitnessProgramInfo 返回版本和程序，如果传递的 脚本是否构成有效的见证程序，
// 则返回版本和程序信息。最后一个返回值表示脚本是否为有效的见证程序。
func extractWitnessProgramInfo(script []byte) (int, []byte, bool) {
	// Skip parsing if we know the program is invalid based on size.
	if len(script) < 4 || len(script) > 42 {
		return 0, nil, false
	}

	const scriptVersion = 0
	tokenizer := MakeScriptTokenizer(scriptVersion, script)

	// The first opcode must be a small int.
	if !tokenizer.Next() ||
		!IsSmallInt(tokenizer.Opcode()) {

		return 0, nil, false
	}
	version := AsSmallInt(tokenizer.Opcode())

	// The second opcode must be a canonical data push, the length of the
	// data push is bounded to 40 by the initial check on overall script
	// length.
	if !tokenizer.Next() ||
		!isCanonicalPush(tokenizer.Opcode(), tokenizer.Data()) {

		return 0, nil, false
	}
	program := tokenizer.Data()

	// The witness program is valid if there are no more opcodes, and we
	// terminated without a parsing error.
	valid := tokenizer.Done() && tokenizer.Err() == nil

	return version, program, valid
}

// 如果传递的脚本是见证程序，isWitnessProgramScript 返回 true，否则返回 false。
// 见证程序必须遵守以下约束：必须有两个弹出窗口（程序版本和程序本身），
// 第一个操作码必须是小整数（0-16），推送数据必须是规范数据，最后，推送数据的大小必须在 2 到 40 字节之间。
//
// 脚本长度必须在 4 至 42 字节之间。最小的程序是见证版本，然后是 2 字节的数据推送。 允许的最大见证程序的数据推送长度为 40 字节。
func isWitnessProgramScript(script []byte) bool {
	_, _, valid := extractWitnessProgramInfo(script)
	return valid
}

// isWitnessTaprootScript 如果传递的脚本是用于支付见证点输出，则返回 true，否则返回 false。
func isWitnessTaprootScript(script []byte) bool {
	return extractWitnessV1KeyBytes(script) != nil
}

// isAnnexedWitness 如果传递的证人有最终推送，则返回 true。
//
//	是见证附件，则返回 true。
func isAnnexedWitness(witness wire.TxWitness) bool {
	if len(witness) < 2 {
		return false
	}

	lastElement := witness[len(witness)-1]
	return len(lastElement) > 0 && lastElement[0] == TaprootAnnexTag
}

// extractAnnex 试图从传递的证人中提取附件。如果 则返回错误信息。
func extractAnnex(witness [][]byte) ([]byte, error) {
	if !isAnnexedWitness(witness) {
		return nil, scriptError(ErrWitnessHasNoAnnex, "")
	}

	lastElement := witness[len(witness)-1]
	return lastElement, nil
}

// isNullDataScript 返回传递的脚本是否为标准空数据脚本。
//
// 注意：此函数仅对版本 0 的脚本有效。 对于其他版本的脚本，它总是返回 false。
func isNullDataScript(scriptVersion uint16, script []byte) bool {
	// The only currently supported script version is 0.
	if scriptVersion != 0 {
		return false
	}

	// A null script is of the form:
	//  OP_RETURN <optional data>
	//
	// Thus, it can either be a single OP_RETURN or an OP_RETURN followed by a
	// data push up to MaxDataCarrierSize bytes.

	// The script can't possibly be a null data script if it doesn't start
	// with OP_RETURN.  Fail fast to avoid more work below.
	if len(script) < 1 || script[0] != OP_RETURN {
		return false
	}

	// Single OP_RETURN.
	if len(script) == 1 {
		return true
	}

	// OP_RETURN followed by data push up to MaxDataCarrierSize bytes.
	tokenizer := MakeScriptTokenizer(scriptVersion, script[1:])
	return tokenizer.Next() && tokenizer.Done() &&
		(IsSmallInt(tokenizer.Opcode()) || tokenizer.Opcode() <= OP_PUSHDATA4) &&
		len(tokenizer.Data()) <= MaxDataCarrierSize
}

// scriptType 返回从已知标准类型中检查的脚本类型。如果脚本是 segwit v0 或更早版本的脚本，
// 版本版本应为 0；segwit v1（taproot）版本的脚本，版本版本应为 1。
func typeOfScript(scriptVersion uint16, script []byte) ScriptClass {
	switch scriptVersion {
	case BaseSegwitWitnessVersion:
		switch {
		case isPubKeyScript(script):
			return PubKeyTy
		case isPubKeyHashScript(script):
			return PubKeyHashTy
		case isScriptHashScript(script):
			return ScriptHashTy
		case isWitnessPubKeyHashScript(script):
			return WitnessV0PubKeyHashTy
		case isWitnessScriptHashScript(script):
			return WitnessV0ScriptHashTy
		case isMultisigScript(scriptVersion, script):
			return MultiSigTy
		case isNullDataScript(scriptVersion, script):
			return NullDataTy
		}
	case TaprootWitnessVersion:
		switch {
		case isWitnessTaprootScript(script):
			return WitnessV1TaprootTy
		}
	}

	return NonStandardTy
}

// GetScriptClass 返回所传递脚本的类。
// 当脚本无法解析时，将返回 NonStandardTy。
func GetScriptClass(script []byte) ScriptClass {
	const scriptVersionSegWit = 0
	classSegWit := typeOfScript(scriptVersionSegWit, script)

	if classSegWit != NonStandardTy {
		return classSegWit
	}

	const scriptVersionTaproot = 1
	return typeOfScript(scriptVersionTaproot, script)
}

// NewScriptClass 返回与作为参数提供的字符串名称相对应的 ScriptClass。
// 如果名称与任何已知 ScriptClass 不对应，则返回 ErrUnsupportedScriptType 错误。不要与 GetScriptClass 混淆。
func NewScriptClass(name string) (*ScriptClass, error) {
	for i, n := range scriptClassToName {
		if n == name {
			value := ScriptClass(i)
			return &value, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrUnsupportedScriptType, name)
}

// expectedInputs 返回脚本所需的参数数。如果脚本类型未知，
// 无法确定参数个数，则返回-1。我们是一个内部函数，
// 因此假定类是 pops 的真实类（因此我们可以假定在找出类型时确定的事情）。
// 注意：该函数仅对版本 0 的脚本有效。 由于该函数不接受脚本版本，因此其结果对于其他脚本 // 版本是未定义的。
// 版本。
func expectedInputs(script []byte, class ScriptClass) int {
	switch class {
	case PubKeyTy:
		return 1

	case PubKeyHashTy:
		return 2

	case WitnessV0PubKeyHashTy:
		return 2

	case ScriptHashTy:
		// Not including script.  That is handled by the caller.
		return 1

	case WitnessV0ScriptHashTy:
		// Not including script.  That is handled by the caller.
		return 1

	case WitnessV1TaprootTy:
		// Not including script.  That is handled by the caller.
		return 1

	case MultiSigTy:
		// Standard multisig has a push a small number for the number
		// of sigs and number of keys.  Check the first push instruction
		// to see how many arguments are expected. typeOfScript already
		// checked this so we know it'll be a small int.  Also, due to
		// the original bitcoind bug where OP_CHECKMULTISIG pops an
		// additional item from the stack, add an extra expected input
		// for the extra push that is required to compensate.
		return AsSmallInt(script[0]) + 1

	case NullDataTy:
		fallthrough
	default:
		return -1
	}
}

// ScriptInfo 包含脚本对的信息，该信息由 CalcScriptInfo.
type ScriptInfo struct {
	// PkScriptClass is the class of the public key script and is equivalent
	// to calling GetScriptClass on it.
	PkScriptClass ScriptClass

	// NumInputs is the number of inputs provided by the public key script.
	NumInputs int

	// ExpectedInputs is the number of outputs required by the signature
	// script and any pay-to-script-hash scripts. The number will be -1 if
	// unknown.
	ExpectedInputs int

	// SigOps is the number of signature operations in the script pair.
	SigOps int
}

// CalcScriptInfo 返回一个结构，提供关于所提供脚本对的数据。
//
//	如果脚本对在某种程度上无效，导致无法分析，即无法解析或 pkScript 不是只推送的脚本，则会出错。
//
// 注意：此函数仅对版本 0 的脚本有效。 由于该函数不接受脚本版本，因此对于其他版本的脚本，结果是未定义的。
//
// 已删除。 该函数将在下一个重大版本更新时删除。
func CalcScriptInfo(sigScript, pkScript []byte, witness wire.TxWitness,
	bip16, segwit bool) (*ScriptInfo, error) {

	// Count the number of opcodes in the signature script while also ensuring
	// that successfully parses.  Since there is a check below to ensure the
	// script is push only, this equates to the number of inputs to the public
	// key script.
	const scriptVersion = 0
	var numInputs int
	tokenizer := MakeScriptTokenizer(scriptVersion, sigScript)
	for tokenizer.Next() {
		numInputs++
	}
	if err := tokenizer.Err(); err != nil {
		return nil, err
	}

	if err := checkScriptParses(scriptVersion, pkScript); err != nil {
		return nil, err
	}

	// Can't have a signature script that doesn't just push data.
	if !IsPushOnlyScript(sigScript) {
		return nil, scriptError(ErrNotPushOnly,
			"signature script is not push only")
	}

	si := new(ScriptInfo)
	si.PkScriptClass = typeOfScript(scriptVersion, pkScript)

	si.ExpectedInputs = expectedInputs(pkScript, si.PkScriptClass)

	switch {
	// Count sigops taking into account pay-to-script-hash.
	case si.PkScriptClass == ScriptHashTy && bip16 && !segwit:
		// The redeem script is the final data push of the signature script.
		redeemScript := finalOpcodeData(scriptVersion, sigScript)
		reedeemClass := typeOfScript(scriptVersion, redeemScript)
		rsInputs := expectedInputs(redeemScript, reedeemClass)
		if rsInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += rsInputs
		}
		si.SigOps = countSigOpsV0(redeemScript, true)

		// All entries pushed to stack (or are OP_RESERVED and exec
		// will fail).
		si.NumInputs = numInputs

	// If segwit is active, and this is a regular p2wkh output, then we'll
	// treat the script as a p2pkh output in essence.
	case si.PkScriptClass == WitnessV0PubKeyHashTy && segwit:

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)
		si.NumInputs = len(witness)

	// We'll attempt to detect the nested p2sh case so we can accurately
	// count the signature operations involved.
	case si.PkScriptClass == ScriptHashTy &&
		IsWitnessProgram(sigScript[1:]) && bip16 && segwit:

		// Extract the pushed witness program from the sigScript so we
		// can determine the number of expected inputs.
		redeemClass := typeOfScript(scriptVersion, sigScript[1:])
		shInputs := expectedInputs(sigScript[1:], redeemClass)
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)

		si.NumInputs = len(witness)
		si.NumInputs += numInputs

	// If segwit is active, and this is a p2wsh output, then we'll need to
	// examine the witness script to generate accurate script info.
	case si.PkScriptClass == WitnessV0ScriptHashTy && segwit:
		witnessScript := witness[len(witness)-1]
		redeemClass := typeOfScript(scriptVersion, witnessScript)
		shInputs := expectedInputs(witnessScript, redeemClass)
		if shInputs == -1 {
			si.ExpectedInputs = -1
		} else {
			si.ExpectedInputs += shInputs
		}

		si.SigOps = GetWitnessSigOpCount(sigScript, pkScript, witness)
		si.NumInputs = len(witness)

	default:
		si.SigOps = countSigOpsV0(pkScript, true)

		// All entries pushed to stack (or are OP_RESERVED and exec
		// will fail).
		si.NumInputs = numInputs
	}

	return si, nil
}

// CalcMultiSigStats 返回来自 多重签名交易脚本的公钥和签名数。 所传递的脚本必须是已知的多重签名脚本。
//
// 注意：此函数仅对版本 0 的脚本有效。 由于该函数不接受脚本版本，因此对于其他版本的脚本，其结果是未定义的。
func CalcMultiSigStats(script []byte) (int, int, error) {
	// The public keys are not needed here, so pass false to avoid the extra
	// allocation.
	const scriptVersion = 0
	details := extractMultisigScriptDetails(scriptVersion, script, false)
	if !details.valid {
		str := fmt.Sprintf("script %x is not a multisig script", script)
		return 0, 0, scriptError(ErrNotMultisigScript, str)
	}

	return details.numPubKeys, details.requiredSigs, nil
}

// payToPubKeyHashScript 创建一个新脚本，用于将交易输出付给一个 20 字节的公开密钥哈希值。预计输入是一个有效的哈希值。
func payToPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_DUP).AddOp(OP_HASH160).
		AddData(pubKeyHash).AddOp(OP_EQUALVERIFY).AddOp(OP_CHECKSIG).
		Script()
}

// payToWitnessPubKeyHashScript 创建一个新脚本，用于向 0 版公钥哈希见证程序付款。所传递的哈希值应是有效的。
func payToWitnessPubKeyHashScript(pubKeyHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_0).AddData(pubKeyHash).Script()
}

// payToScriptHashScript 创建一个新脚本，将交易输出支付到 脚本哈希值。预期输入是一个有效的哈希值。
func payToScriptHashScript(scriptHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_HASH160).AddData(scriptHash).
		AddOp(OP_EQUAL).Script()
}

// payToWitnessPubKeyHashScript 创建一个新脚本，用于向版本 0 版本的哈希见证程序。所传递的哈希值应是有效的。
func payToWitnessScriptHashScript(scriptHash []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_0).AddData(scriptHash).Script()
}

// payToWitnessTaprootScript 会创建一个新脚本，用于向版本 1（taproot）见证程序付款。所传递的哈希值应是有效的。
func payToWitnessTaprootScript(rawKey []byte) ([]byte, error) {
	return NewScriptBuilder().AddOp(OP_1).AddData(rawKey).Script()
}

// payToPubkeyScript 创建一个新脚本，用于将交易输出付给公钥。预期输入是一个有效的公钥。
func payToPubKeyScript(serializedPubKey []byte) ([]byte, error) {
	return NewScriptBuilder().AddData(serializedPubKey).
		AddOp(OP_CHECKSIG).Script()
}

// PayToAddrScript 创建一个新脚本，用于向指定地址支付交易输出。
func PayToAddrScript(addr btcutil.Address) ([]byte, error) {
	const nilAddrErrStr = "unable to generate payment script for nil address"

	switch addr := addr.(type) {
	case *btcutil.AddressPubKeyHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToPubKeyHashScript(addr.ScriptAddress())

	case *btcutil.AddressScriptHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToScriptHashScript(addr.ScriptAddress())

	case *btcutil.AddressPubKey:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToPubKeyScript(addr.ScriptAddress())

	case *btcutil.AddressWitnessPubKeyHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToWitnessPubKeyHashScript(addr.ScriptAddress())
	case *btcutil.AddressWitnessScriptHash:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToWitnessScriptHashScript(addr.ScriptAddress())
	case *btcutil.AddressTaproot:
		if addr == nil {
			return nil, scriptError(ErrUnsupportedAddress,
				nilAddrErrStr)
		}
		return payToWitnessTaprootScript(addr.ScriptAddress())
	}

	str := fmt.Sprintf("unable to generate payment script for unsupported "+
		"address type %T", addr)
	return nil, scriptError(ErrUnsupportedAddress, str)
}

// NullDataScript 会创建一个可证明可裁剪的脚本，该脚本包含 OP_RETURN，后面跟传入的数据。
// 如果传递的数据长度超过 MaxDataCarrierSize，将返回错误代码为 ErrTooMuchNullData 的错误信息。
func NullDataScript(data []byte) ([]byte, error) {
	if len(data) > MaxDataCarrierSize {
		str := fmt.Sprintf("data size %d is larger than max "+
			"allowed size %d", len(data), MaxDataCarrierSize)
		return nil, scriptError(ErrTooMuchNullData, str)
	}

	return NewScriptBuilder().AddOp(OP_RETURN).AddData(data).Script()
}

// MultiSigScript 返回多签名赎回的有效脚本，其中
//
//	如果 nrequired 大于所提供的密钥数，将返回错误代码为 ErrTooManyRequiredSigs 的错误信息。
func MultiSigScript(pubkeys []*btcutil.AddressPubKey, nrequired int) ([]byte, error) {
	if len(pubkeys) < nrequired {
		str := fmt.Sprintf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", nrequired, len(pubkeys))
		return nil, scriptError(ErrTooManyRequiredSigs, str)
	}

	builder := NewScriptBuilder().AddInt64(int64(nrequired))
	for _, key := range pubkeys {
		builder.AddData(key.ScriptAddress())
	}
	builder.AddInt64(int64(len(pubkeys)))
	builder.AddOp(OP_CHECKMULTISIG)

	return builder.Script()
}

// PushedData 返回一个字节片数组，其中包含在传递的脚本中找到的任何推送数据。 这包括 OP_0，但不包括 OP_1 - OP_16。
func PushedData(script []byte) ([][]byte, error) {
	const scriptVersion = 0

	var data [][]byte
	tokenizer := MakeScriptTokenizer(scriptVersion, script)
	for tokenizer.Next() {
		if tokenizer.Data() != nil {
			data = append(data, tokenizer.Data())
		} else if tokenizer.Opcode() == OP_0 {
			data = append(data, nil)
		}
	}
	if err := tokenizer.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

// pubKeyHashToAddrs 是一个方便的函数，用于尝试将传递的哈希值转换为地址片中的支付到公钥哈希值地址。 该函数用于合并常用代码。
func pubKeyHashToAddrs(hash []byte, params *chaincfg.Params) []btcutil.Address {
	// Skip the pubkey hash if it's invalid for some reason.
	var addrs []btcutil.Address
	addr, err := btcutil.NewAddressPubKeyHash(hash, params)
	if err == nil {
		addrs = append(addrs, addr)
	}
	return addrs
}

// scriptHashToAddrs 是一个方便的函数，用于尝试将传递的哈希值转换为地址片中的付费到脚本哈希值地址。 它用于合并常用代码。
func scriptHashToAddrs(hash []byte, params *chaincfg.Params) []btcutil.Address {
	// Skip the hash if it's invalid for some reason.
	var addrs []btcutil.Address
	addr, err := btcutil.NewAddressScriptHashFromHash(hash, params)
	if err == nil {
		addrs = append(addrs, addr)
	}
	return addrs
}

// ExtractPkScriptAddrs 返回与传递的 PkScript 相关的脚本类型、地址和所需签名。
// 请注意，它只适用于 "标准 "交易脚本类型。 结果中将省略任何无效数据，如公钥。
func ExtractPkScriptAddrs(pkScript []byte,
	chainParams *chaincfg.Params) (ScriptClass, []btcutil.Address, int, error) {

	// Check for pay-to-pubkey-hash script.
	if hash := extractPubKeyHash(pkScript); hash != nil {
		return PubKeyHashTy, pubKeyHashToAddrs(hash, chainParams), 1, nil
	}

	// Check for pay-to-script-hash.
	if hash := extractScriptHash(pkScript); hash != nil {
		return ScriptHashTy, scriptHashToAddrs(hash, chainParams), 1, nil
	}

	// Check for pay-to-pubkey script.
	if data := extractPubKey(pkScript); data != nil {
		var addrs []btcutil.Address
		addr, err := btcutil.NewAddressPubKey(data, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}
		return PubKeyTy, addrs, 1, nil
	}

	// Check for multi-signature script.
	const scriptVersion = 0
	details := extractMultisigScriptDetails(scriptVersion, pkScript, true)
	if details.valid {
		// Convert the public keys while skipping any that are invalid.
		addrs := make([]btcutil.Address, 0, len(details.pubKeys))
		for _, pubkey := range details.pubKeys {
			addr, err := btcutil.NewAddressPubKey(pubkey, chainParams)
			if err == nil {
				addrs = append(addrs, addr)
			}
		}
		return MultiSigTy, addrs, details.requiredSigs, nil
	}

	// Check for null data script.
	if isNullDataScript(scriptVersion, pkScript) {
		// Null data transactions have no addresses or required signatures.
		return NullDataTy, nil, 0, nil
	}

	if hash := extractWitnessPubKeyHash(pkScript); hash != nil {
		var addrs []btcutil.Address
		addr, err := btcutil.NewAddressWitnessPubKeyHash(hash, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}
		return WitnessV0PubKeyHashTy, addrs, 1, nil
	}

	if hash := extractWitnessV0ScriptHash(pkScript); hash != nil {
		var addrs []btcutil.Address
		addr, err := btcutil.NewAddressWitnessScriptHash(hash, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}
		return WitnessV0ScriptHashTy, addrs, 1, nil
	}

	if rawKey := extractWitnessV1KeyBytes(pkScript); rawKey != nil {
		var addrs []btcutil.Address
		addr, err := btcutil.NewAddressTaproot(rawKey, chainParams)
		if err == nil {
			addrs = append(addrs, addr)
		}
		return WitnessV1TaprootTy, addrs, 1, nil
	}

	// If none of the above passed, then the address must be non-standard.
	return NonStandardTy, nil, 0, nil
}

// AtomicSwapDataPushes 包含原子交换合约中的数据推送。
type AtomicSwapDataPushes struct {
	RecipientHash160 [20]byte
	RefundHash160    [20]byte
	SecretHash       [32]byte
	SecretSize       int64
	LockTime         int64
}

// ExtractAtomicSwapDataPushes 返回原子互换合约的数据推送。 如果脚本不是原子交换合约，ExtractAtomicSwapDataPushes 将返回（nil, nil）。 对于无法解析的脚本，将返回非零错误。
//
// 注意：根据 dcrd 内存池策略，原子交换不属于标准脚本类型，应与 P2SH 一起使用。 原子交换格式预计在未来也会改变，以使用更安全的哈希函数。
// 由于 API 的限制，调用者无法使用 txscript 解析非标准脚本，因此该函数仅在 txscript 包中定义。
//
// 已删除。 在下一个重大版本更新时，该错误将被删除。 如果代码被任何调用者重新实现，该错误也可能被移除。
// 因为任何错误都会导致结果为空。
func ExtractAtomicSwapDataPushes(version uint16, pkScript []byte) (*AtomicSwapDataPushes, error) {
	// An atomic swap is of the form:
	//  IF
	//   SIZE <secret size> EQUALVERIFY SHA256 <32-byte secret> EQUALVERIFY DUP
	//   HASH160 <20-byte recipient hash>
	//  ELSE
	//   <locktime> CHECKLOCKTIMEVERIFY DROP DUP HASH160 <20-byte refund hash>
	//  ENDIF
	//  EQUALVERIFY CHECKSIG
	type templateMatch struct {
		expectCanonicalInt bool
		maxIntBytes        int
		opcode             byte
		extractedInt       int64
		extractedData      []byte
	}
	var template = [20]templateMatch{
		{opcode: OP_IF},
		{opcode: OP_SIZE},
		{expectCanonicalInt: true, maxIntBytes: maxScriptNumLen},
		{opcode: OP_EQUALVERIFY},
		{opcode: OP_SHA256},
		{opcode: OP_DATA_32},
		{opcode: OP_EQUALVERIFY},
		{opcode: OP_DUP},
		{opcode: OP_HASH160},
		{opcode: OP_DATA_20},
		{opcode: OP_ELSE},
		{expectCanonicalInt: true, maxIntBytes: cltvMaxScriptNumLen},
		{opcode: OP_CHECKLOCKTIMEVERIFY},
		{opcode: OP_DROP},
		{opcode: OP_DUP},
		{opcode: OP_HASH160},
		{opcode: OP_DATA_20},
		{opcode: OP_ENDIF},
		{opcode: OP_EQUALVERIFY},
		{opcode: OP_CHECKSIG},
	}

	var templateOffset int
	tokenizer := MakeScriptTokenizer(version, pkScript)
	for tokenizer.Next() {
		// Not an atomic swap script if it has more opcodes than expected in the
		// template.
		if templateOffset >= len(template) {
			return nil, nil
		}

		op := tokenizer.Opcode()
		data := tokenizer.Data()
		tplEntry := &template[templateOffset]
		if tplEntry.expectCanonicalInt {
			switch {
			case data != nil:
				val, err := MakeScriptNum(data, true, tplEntry.maxIntBytes)
				if err != nil {
					return nil, err
				}
				tplEntry.extractedInt = int64(val)

			case IsSmallInt(op):
				tplEntry.extractedInt = int64(AsSmallInt(op))

			// Not an atomic swap script if the opcode does not push an int.
			default:
				return nil, nil
			}
		} else {
			if op != tplEntry.opcode {
				return nil, nil
			}

			tplEntry.extractedData = data
		}

		templateOffset++
	}
	if err := tokenizer.Err(); err != nil {
		return nil, err
	}
	if !tokenizer.Done() || templateOffset != len(template) {
		return nil, nil
	}

	// At this point, the script appears to be an atomic swap, so populate and
	// return the extacted data.
	pushes := AtomicSwapDataPushes{
		SecretSize: template[2].extractedInt,
		LockTime:   template[11].extractedInt,
	}
	copy(pushes.SecretHash[:], template[5].extractedData)
	copy(pushes.RecipientHash160[:], template[9].extractedData)
	copy(pushes.RefundHash160[:], template[16].extractedData)
	return &pushes, nil
}
