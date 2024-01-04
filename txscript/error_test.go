// 包含测试 error.go 中定义的错误类型的代码。
package txscript

import (
	"testing"
)

// TestErrorCodeStringer 测试 ErrorCode 类型的字符串化输出。
func TestErrorCodeStringer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   ErrorCode
		want string
	}{
		{ErrInternal, "ErrInternal"},
		{ErrInvalidFlags, "ErrInvalidFlags"},
		{ErrInvalidIndex, "ErrInvalidIndex"},
		{ErrUnsupportedAddress, "ErrUnsupportedAddress"},
		{ErrTooManyRequiredSigs, "ErrTooManyRequiredSigs"},
		{ErrTooMuchNullData, "ErrTooMuchNullData"},
		{ErrUnsupportedScriptVersion, "ErrUnsupportedScriptVersion"},
		{ErrNotMultisigScript, "ErrNotMultisigScript"},
		{ErrEarlyReturn, "ErrEarlyReturn"},
		{ErrEmptyStack, "ErrEmptyStack"},
		{ErrEvalFalse, "ErrEvalFalse"},
		{ErrScriptUnfinished, "ErrScriptUnfinished"},
		{ErrInvalidProgramCounter, "ErrInvalidProgramCounter"},
		{ErrScriptTooBig, "ErrScriptTooBig"},
		{ErrElementTooBig, "ErrElementTooBig"},
		{ErrTooManyOperations, "ErrTooManyOperations"},
		{ErrStackOverflow, "ErrStackOverflow"},
		{ErrInvalidPubKeyCount, "ErrInvalidPubKeyCount"},
		{ErrInvalidSignatureCount, "ErrInvalidSignatureCount"},
		{ErrNumberTooBig, "ErrNumberTooBig"},
		{ErrVerify, "ErrVerify"},
		{ErrEqualVerify, "ErrEqualVerify"},
		{ErrNumEqualVerify, "ErrNumEqualVerify"},
		{ErrCheckSigVerify, "ErrCheckSigVerify"},
		{ErrCheckMultiSigVerify, "ErrCheckMultiSigVerify"},
		{ErrDisabledOpcode, "ErrDisabledOpcode"},
		{ErrReservedOpcode, "ErrReservedOpcode"},
		{ErrMalformedPush, "ErrMalformedPush"},
		{ErrInvalidStackOperation, "ErrInvalidStackOperation"},
		{ErrUnbalancedConditional, "ErrUnbalancedConditional"},
		{ErrMinimalData, "ErrMinimalData"},
		{ErrInvalidSigHashType, "ErrInvalidSigHashType"},
		{ErrSigTooShort, "ErrSigTooShort"},
		{ErrSigTooLong, "ErrSigTooLong"},
		{ErrSigInvalidSeqID, "ErrSigInvalidSeqID"},
		{ErrSigInvalidDataLen, "ErrSigInvalidDataLen"},
		{ErrSigMissingSTypeID, "ErrSigMissingSTypeID"},
		{ErrSigMissingSLen, "ErrSigMissingSLen"},
		{ErrSigInvalidSLen, "ErrSigInvalidSLen"},
		{ErrSigInvalidRIntID, "ErrSigInvalidRIntID"},
		{ErrSigZeroRLen, "ErrSigZeroRLen"},
		{ErrSigNegativeR, "ErrSigNegativeR"},
		{ErrSigTooMuchRPadding, "ErrSigTooMuchRPadding"},
		{ErrSigInvalidSIntID, "ErrSigInvalidSIntID"},
		{ErrSigZeroSLen, "ErrSigZeroSLen"},
		{ErrSigNegativeS, "ErrSigNegativeS"},
		{ErrSigTooMuchSPadding, "ErrSigTooMuchSPadding"},
		{ErrSigHighS, "ErrSigHighS"},
		{ErrNotPushOnly, "ErrNotPushOnly"},
		{ErrSigNullDummy, "ErrSigNullDummy"},
		{ErrPubKeyType, "ErrPubKeyType"},
		{ErrCleanStack, "ErrCleanStack"},
		{ErrNullFail, "ErrNullFail"},
		{ErrDiscourageUpgradableNOPs, "ErrDiscourageUpgradableNOPs"},
		{ErrNegativeLockTime, "ErrNegativeLockTime"},
		{ErrUnsatisfiedLockTime, "ErrUnsatisfiedLockTime"},
		{ErrWitnessProgramEmpty, "ErrWitnessProgramEmpty"},
		{ErrWitnessProgramMismatch, "ErrWitnessProgramMismatch"},
		{ErrWitnessProgramWrongLength, "ErrWitnessProgramWrongLength"},
		{ErrWitnessMalleated, "ErrWitnessMalleated"},
		{ErrWitnessMalleatedP2SH, "ErrWitnessMalleatedP2SH"},
		{ErrWitnessUnexpected, "ErrWitnessUnexpected"},
		{ErrMinimalIf, "ErrMinimalIf"},
		{ErrWitnessPubKeyType, "ErrWitnessPubKeyType"},
		{ErrDiscourageOpSuccess, "ErrDiscourageOpSuccess"},
		{ErrDiscourageUpgradeableTaprootVersion, "ErrDiscourageUpgradeableTaprootVersion"},
		{ErrTapscriptCheckMultisig, "ErrTapscriptCheckMultisig"},
		{ErrDiscourageUpgradableWitnessProgram, "ErrDiscourageUpgradableWitnessProgram"},
		{ErrDiscourageUpgradeablePubKeyType, "ErrDiscourageUpgradeablePubKeyType"},
		{ErrTaprootSigInvalid, "ErrTaprootSigInvalid"},
		{ErrTaprootMerkleProofInvalid, "ErrTaprootMerkleProofInvalid"},
		{ErrTaprootOutputKeyParityMismatch, "ErrTaprootOutputKeyParityMismatch"},
		{ErrControlBlockTooSmall, "ErrControlBlockTooSmall"},
		{ErrControlBlockTooLarge, "ErrControlBlockTooLarge"},
		{ErrControlBlockInvalidLength, "ErrControlBlockInvalidLength"},
		{ErrWitnessHasNoAnnex, "ErrWitnessHasNoAnnex"},
		{ErrInvalidTaprootSigLen, "ErrInvalidTaprootSigLen"},
		{ErrTaprootPubkeyIsEmpty, "ErrTaprootPubkeyIsEmpty"},
		{ErrTaprootMaxSigOps, "ErrTaprootMaxSigOps"},
		{0xffff, "Unknown ErrorCode (65535)"},
	}

	// 检测未添加纵梁的其他错误代码。
	if len(tests)-1 != int(numErrorCodes) {
		t.Errorf("It appears an error code was added without adding an " +
			"associated stringer test")
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.String()
		if result != test.want {
			t.Errorf("String #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}

// TestError 测试错误类型的错误输出。
func TestError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   Error
		want string
	}{
		{
			Error{Description: "some error"},
			"some error",
		},
		{
			Error{Description: "human-readable error"},
			"human-readable error",
		},
	}

	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		result := test.in.Error()
		if result != test.want {
			t.Errorf("Error #%d\n got: %s want: %s", i, result,
				test.want)
			continue
		}
	}
}
