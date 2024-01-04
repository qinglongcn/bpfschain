package bpfschain

import (
	"fmt"

	"github.com/btcsuite/btcd/txscript"
)

const (
	// maxStandardMultiSigKeys 是多重签名交易输出脚本中允许的最大公钥数量，以便将其视为标准。
	maxStandardMultiSigKeys = 3
)

// checkPkScriptStandard 对交易输出脚本（公钥脚本）执行一系列检查，以确保它是“标准”公钥脚本。
// 标准公钥脚本是一种可识别的形式，对于多重签名脚本，仅包含 1 到 maxStandardMultiSigKeys 个公钥。
func checkPkScriptStandard(pkScript []byte, scriptClass txscript.ScriptClass) error {
	switch scriptClass {
	case txscript.MultiSigTy:
		numPubKeys, numSigs, err := txscript.CalcMultiSigStats(pkScript)
		if err != nil {
			return fmt.Errorf("multi-signature script parse failure: %v", err)
		}

		// 标准多重签名公钥脚本必须包含 1 到 maxStandardMultiSigKeys 个公钥。
		if numPubKeys < 1 {
			return fmt.Errorf("multi-signature script with no pubkeys")
		}
		if numPubKeys > maxStandardMultiSigKeys {
			return fmt.Errorf("multi-signature script with %d public keys which is more than the allowed max of %d", numPubKeys, maxStandardMultiSigKeys)
		}

		// 标准多重签名公钥脚本必须至少有 1 个签名，且签名数量不得多于可用公钥。
		if numSigs < 1 {
			return fmt.Errorf("multi-signature script with no signatures")
		}
		if numSigs > numPubKeys {
			return fmt.Errorf("multi-signature script with %d signatures which is more than the available %d public keys", numSigs, numPubKeys)
		}

	case txscript.NonStandardTy:
		return fmt.Errorf("non-standard script form")
	}

	return nil
}
