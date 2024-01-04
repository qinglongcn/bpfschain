// 包含测试脚本数字处理的代码。

package txscript

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// hexToBytes 将传递的十六进制字符串转换为字节，如果出现错误将会出现错误。
// 这仅针对硬编码常量提供，以便可以检测到源代码中的错误。
// 它只会（并且必须仅）使用硬编码值来调用。
func hexToBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex in source file: " + s)
	}
	return b
}

// TestScriptNumBytes 确保从整数脚本数字到字节表示的转换按预期工作。
func TestScriptNumBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		num        scriptNum
		serialized []byte
	}{
		{0, nil},
		{1, hexToBytes("01")},
		{-1, hexToBytes("81")},
		{127, hexToBytes("7f")},
		{-127, hexToBytes("ff")},
		{128, hexToBytes("8000")},
		{-128, hexToBytes("8080")},
		{129, hexToBytes("8100")},
		{-129, hexToBytes("8180")},
		{256, hexToBytes("0001")},
		{-256, hexToBytes("0081")},
		{32767, hexToBytes("ff7f")},
		{-32767, hexToBytes("ffff")},
		{32768, hexToBytes("008000")},
		{-32768, hexToBytes("008080")},
		{65535, hexToBytes("ffff00")},
		{-65535, hexToBytes("ffff80")},
		{524288, hexToBytes("000008")},
		{-524288, hexToBytes("000088")},
		{7340032, hexToBytes("000070")},
		{-7340032, hexToBytes("0000f0")},
		{8388608, hexToBytes("00008000")},
		{-8388608, hexToBytes("00008080")},
		{2147483647, hexToBytes("ffffff7f")},
		{-2147483647, hexToBytes("ffffffff")},

		// 超出被解释为数字的数据范围的值，但允许作为数字运算的结果。
		{2147483648, hexToBytes("0000008000")},
		{-2147483648, hexToBytes("0000008080")},
		{2415919104, hexToBytes("0000009000")},
		{-2415919104, hexToBytes("0000009080")},
		{4294967295, hexToBytes("ffffffff00")},
		{-4294967295, hexToBytes("ffffffff80")},
		{4294967296, hexToBytes("0000000001")},
		{-4294967296, hexToBytes("0000000081")},
		{281474976710655, hexToBytes("ffffffffffff00")},
		{-281474976710655, hexToBytes("ffffffffffff80")},
		{72057594037927935, hexToBytes("ffffffffffffff00")},
		{-72057594037927935, hexToBytes("ffffffffffffff80")},
		{9223372036854775807, hexToBytes("ffffffffffffff7f")},
		{-9223372036854775807, hexToBytes("ffffffffffffffff")},
	}

	for _, test := range tests {
		gotBytes := test.num.Bytes()
		if !bytes.Equal(gotBytes, test.serialized) {
			t.Errorf("Bytes: did not get expected bytes for %d - "+
				"got %x, want %x", test.num, gotBytes,
				test.serialized)
			continue
		}
	}
}

// TestMakeScriptNum 确保从字节表示形式转换为整数脚本数字按预期工作。
func TestMakeScriptNum(t *testing.T) {
	t.Parallel()

	// 为了方便起见并保持水平测试尺寸更短，这里定义了下面测试中使用的误差。
	errNumTooBig := scriptError(ErrNumberTooBig, "")
	errMinimalData := scriptError(ErrMinimalData, "")

	tests := []struct {
		serialized      []byte
		num             scriptNum
		numLen          int
		minimalEncoding bool
		err             error
	}{
		// 最小编码必须拒绝负 0。
		{hexToBytes("80"), 0, maxScriptNumLen, true, errMinimalData},

		// 具有最小编码标志的最小编码有效值。
		// 不应出错并返回预期的整数。
		{nil, 0, maxScriptNumLen, true, nil},
		{hexToBytes("01"), 1, maxScriptNumLen, true, nil},
		{hexToBytes("81"), -1, maxScriptNumLen, true, nil},
		{hexToBytes("7f"), 127, maxScriptNumLen, true, nil},
		{hexToBytes("ff"), -127, maxScriptNumLen, true, nil},
		{hexToBytes("8000"), 128, maxScriptNumLen, true, nil},
		{hexToBytes("8080"), -128, maxScriptNumLen, true, nil},
		{hexToBytes("8100"), 129, maxScriptNumLen, true, nil},
		{hexToBytes("8180"), -129, maxScriptNumLen, true, nil},
		{hexToBytes("0001"), 256, maxScriptNumLen, true, nil},
		{hexToBytes("0081"), -256, maxScriptNumLen, true, nil},
		{hexToBytes("ff7f"), 32767, maxScriptNumLen, true, nil},
		{hexToBytes("ffff"), -32767, maxScriptNumLen, true, nil},
		{hexToBytes("008000"), 32768, maxScriptNumLen, true, nil},
		{hexToBytes("008080"), -32768, maxScriptNumLen, true, nil},
		{hexToBytes("ffff00"), 65535, maxScriptNumLen, true, nil},
		{hexToBytes("ffff80"), -65535, maxScriptNumLen, true, nil},
		{hexToBytes("000008"), 524288, maxScriptNumLen, true, nil},
		{hexToBytes("000088"), -524288, maxScriptNumLen, true, nil},
		{hexToBytes("000070"), 7340032, maxScriptNumLen, true, nil},
		{hexToBytes("0000f0"), -7340032, maxScriptNumLen, true, nil},
		{hexToBytes("00008000"), 8388608, maxScriptNumLen, true, nil},
		{hexToBytes("00008080"), -8388608, maxScriptNumLen, true, nil},
		{hexToBytes("ffffff7f"), 2147483647, maxScriptNumLen, true, nil},
		{hexToBytes("ffffffff"), -2147483647, maxScriptNumLen, true, nil},
		{hexToBytes("ffffffff7f"), 549755813887, 5, true, nil},
		{hexToBytes("ffffffffff"), -549755813887, 5, true, nil},
		{hexToBytes("ffffffffffffff7f"), 9223372036854775807, 8, true, nil},
		{hexToBytes("ffffffffffffffff"), -9223372036854775807, 8, true, nil},
		{hexToBytes("ffffffffffffffff7f"), -1, 9, true, nil},
		{hexToBytes("ffffffffffffffffff"), 1, 9, true, nil},
		{hexToBytes("ffffffffffffffffff7f"), -1, 10, true, nil},
		{hexToBytes("ffffffffffffffffffff"), 1, 10, true, nil},

		// 最小编码值超出了被解释为具有最小编码标志集的脚本编号的数据范围。
		// 应该出错并返回 0。
		{hexToBytes("0000008000"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("0000008080"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("0000009000"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("0000009080"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffff00"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffff80"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("0000000001"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("0000000081"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffffffff00"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffffffff80"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffffffffff00"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffffffffff80"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffffffffff7f"), 0, maxScriptNumLen, true, errNumTooBig},
		{hexToBytes("ffffffffffffffff"), 0, maxScriptNumLen, true, errNumTooBig},

		// 非最小编码，但具有最小编码标志的有效值。
		// 应该出错并返回 0。
		{hexToBytes("00"), 0, maxScriptNumLen, true, errMinimalData},       // 0
		{hexToBytes("0100"), 0, maxScriptNumLen, true, errMinimalData},     // 1
		{hexToBytes("7f00"), 0, maxScriptNumLen, true, errMinimalData},     // 127
		{hexToBytes("800000"), 0, maxScriptNumLen, true, errMinimalData},   // 128
		{hexToBytes("810000"), 0, maxScriptNumLen, true, errMinimalData},   // 129
		{hexToBytes("000100"), 0, maxScriptNumLen, true, errMinimalData},   // 256
		{hexToBytes("ff7f00"), 0, maxScriptNumLen, true, errMinimalData},   // 32767
		{hexToBytes("00800000"), 0, maxScriptNumLen, true, errMinimalData}, // 32768
		{hexToBytes("ffff0000"), 0, maxScriptNumLen, true, errMinimalData}, // 65535
		{hexToBytes("00000800"), 0, maxScriptNumLen, true, errMinimalData}, // 524288
		{hexToBytes("00007000"), 0, maxScriptNumLen, true, errMinimalData}, // 7340032
		{hexToBytes("0009000100"), 0, 5, true, errMinimalData},             // 16779520

		// 非最小编码，但没有最小编码标志的有效值。
		// 不应出错并返回预期的整数。
		{hexToBytes("00"), 0, maxScriptNumLen, false, nil},
		{hexToBytes("0100"), 1, maxScriptNumLen, false, nil},
		{hexToBytes("7f00"), 127, maxScriptNumLen, false, nil},
		{hexToBytes("800000"), 128, maxScriptNumLen, false, nil},
		{hexToBytes("810000"), 129, maxScriptNumLen, false, nil},
		{hexToBytes("000100"), 256, maxScriptNumLen, false, nil},
		{hexToBytes("ff7f00"), 32767, maxScriptNumLen, false, nil},
		{hexToBytes("00800000"), 32768, maxScriptNumLen, false, nil},
		{hexToBytes("ffff0000"), 65535, maxScriptNumLen, false, nil},
		{hexToBytes("00000800"), 524288, maxScriptNumLen, false, nil},
		{hexToBytes("00007000"), 7340032, maxScriptNumLen, false, nil},
		{hexToBytes("0009000100"), 16779520, 5, false, nil},
	}

	for _, test := range tests {
		// 确保错误代码是预期的类型，并且错误代码与测试实例中指定的值匹配。
		gotNum, err := MakeScriptNum(test.serialized, test.minimalEncoding,
			test.numLen)
		if e := tstCheckScriptError(err, test.err); e != nil {
			t.Errorf("MakeScriptNum(%#x): %v", test.serialized, e)
			continue
		}

		if gotNum != test.num {
			t.Errorf("MakeScriptNum(%#x): did not get expected "+
				"number - got %d, want %d", test.serialized,
				gotNum, test.num)
			continue
		}
	}
}

// TestScriptNumInt32 确保脚本编号上的 Int32 函数按预期运行。
func TestScriptNumInt32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   scriptNum
		want int32
	}{
		// 有效 int32 范围内的值只是转换为 int32 的值本身。
		{0, 0},
		{1, 1},
		{-1, -1},
		{127, 127},
		{-127, -127},
		{128, 128},
		{-128, -128},
		{129, 129},
		{-129, -129},
		{256, 256},
		{-256, -256},
		{32767, 32767},
		{-32767, -32767},
		{32768, 32768},
		{-32768, -32768},
		{65535, 65535},
		{-65535, -65535},
		{524288, 524288},
		{-524288, -524288},
		{7340032, 7340032},
		{-7340032, -7340032},
		{8388608, 8388608},
		{-8388608, -8388608},
		{2147483647, 2147483647},
		{-2147483647, -2147483647},
		{-2147483648, -2147483648},

		// 有效 int32 范围之外的值仅限于 int32。
		{2147483648, 2147483647},
		{-2147483649, -2147483648},
		{1152921504606846975, 2147483647},
		{-1152921504606846975, -2147483648},
		{2305843009213693951, 2147483647},
		{-2305843009213693951, -2147483648},
		{4611686018427387903, 2147483647},
		{-4611686018427387903, -2147483648},
		{9223372036854775807, 2147483647},
		{-9223372036854775808, -2147483648},
	}

	for _, test := range tests {
		got := test.in.Int32()
		if got != test.want {
			t.Errorf("Int32: did not get expected value for %d - "+
				"got %d, want %d", test.in, got, test.want)
			continue
		}
	}
}
