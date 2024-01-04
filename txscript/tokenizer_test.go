// 包含测试脚本令牌化功能的代码。

package txscript

import (
	"bytes"
	"fmt"
	"testing"
)

// TestScriptTokenizer 确保脚本标记生成器提供的各种行为按预期执行。
func TestScriptTokenizer(t *testing.T) {
	t.Skip()

	type expectedResult struct {
		op    byte   // 预期解析的操作码
		data  []byte // 预期解析数据
		index int32  // 解析令牌后原始脚本的预期索引
	}

	type tokenizerTest struct {
		name     string           // 测试说明
		script   []byte           // 要标记化的脚本
		expected []expectedResult // 解析每个标记后的预期信息
		finalIdx int32            // 预期的最终字节索引
		err      error            // 预期错误
	}

	// 添加 OP_DATA_1 到 OP_DATA_75 的正面和负面测试。
	const numTestsHint = 100 // 让预分配 linter 满意。
	tests := make([]tokenizerTest, 0, numTestsHint)
	for op := byte(OP_DATA_1); op < OP_DATA_75; op++ {
		data := bytes.Repeat([]byte{0x01}, int(op))
		tests = append(tests, tokenizerTest{
			name:     fmt.Sprintf("OP_DATA_%d", op),
			script:   append([]byte{op}, data...),
			expected: []expectedResult{{op, data, 1 + int32(op)}},
			finalIdx: 1 + int32(op),
			err:      nil,
		})

		// 创建比数据推送所需少 1 个字节的测试。
		tests = append(tests, tokenizerTest{
			name:     fmt.Sprintf("short OP_DATA_%d", op),
			script:   append([]byte{op}, data[1:]...),
			expected: nil,
			finalIdx: 0,
			err:      scriptError(ErrMalformedPush, ""),
		})
	}

	// 为 OP_PUSHDATA{1,2,4} 添加正面和负面测试。
	data := mustParseShortForm("0x01{76}")
	tests = append(tests, []tokenizerTest{{
		name:     "OP_PUSHDATA1",
		script:   mustParseShortForm("OP_PUSHDATA1 0x4c 0x01{76}"),
		expected: []expectedResult{{OP_PUSHDATA1, data, 2 + int32(len(data))}},
		finalIdx: 2 + int32(len(data)),
		err:      nil,
	}, {
		name:     "OP_PUSHDATA1 no data length",
		script:   mustParseShortForm("OP_PUSHDATA1"),
		expected: nil,
		finalIdx: 0,
		err:      scriptError(ErrMalformedPush, ""),
	}, {
		name:     "OP_PUSHDATA1 short data by 1 byte",
		script:   mustParseShortForm("OP_PUSHDATA1 0x4c 0x01{75}"),
		expected: nil,
		finalIdx: 0,
		err:      scriptError(ErrMalformedPush, ""),
	}, {
		name:     "OP_PUSHDATA2",
		script:   mustParseShortForm("OP_PUSHDATA2 0x4c00 0x01{76}"),
		expected: []expectedResult{{OP_PUSHDATA2, data, 3 + int32(len(data))}},
		finalIdx: 3 + int32(len(data)),
		err:      nil,
	}, {
		name:     "OP_PUSHDATA2 no data length",
		script:   mustParseShortForm("OP_PUSHDATA2"),
		expected: nil,
		finalIdx: 0,
		err:      scriptError(ErrMalformedPush, ""),
	}, {
		name:     "OP_PUSHDATA2 short data by 1 byte",
		script:   mustParseShortForm("OP_PUSHDATA2 0x4c00 0x01{75}"),
		expected: nil,
		finalIdx: 0,
		err:      scriptError(ErrMalformedPush, ""),
	}, {
		name:     "OP_PUSHDATA4",
		script:   mustParseShortForm("OP_PUSHDATA4 0x4c000000 0x01{76}"),
		expected: []expectedResult{{OP_PUSHDATA4, data, 5 + int32(len(data))}},
		finalIdx: 5 + int32(len(data)),
		err:      nil,
	}, {
		name:     "OP_PUSHDATA4 no data length",
		script:   mustParseShortForm("OP_PUSHDATA4"),
		expected: nil,
		finalIdx: 0,
		err:      scriptError(ErrMalformedPush, ""),
	}, {
		name:     "OP_PUSHDATA4 short data by 1 byte",
		script:   mustParseShortForm("OP_PUSHDATA4 0x4c000000 0x01{75}"),
		expected: nil,
		finalIdx: 0,
		err:      scriptError(ErrMalformedPush, ""),
	}}...)

	// 添加 OP_0 和 OP_1 到 OP_16 的测试（小整数/真/假）。
	opcodes := []byte{OP_0}
	for op := byte(OP_1); op < OP_16; op++ {
		opcodes = append(opcodes, op)
	}
	for _, op := range opcodes {
		tests = append(tests, tokenizerTest{
			name:     fmt.Sprintf("OP_%d", op),
			script:   []byte{op},
			expected: []expectedResult{{op, nil, 1}},
			finalIdx: 1,
			err:      nil,
		})
	}

	// 为多操作码脚本添加各种正面和负面测试。
	tests = append(tests, []tokenizerTest{{
		name:   "pay-to-pubkey-hash",
		script: mustParseShortForm("DUP HASH160 DATA_20 0x01{20} EQUAL CHECKSIG"),
		expected: []expectedResult{
			{OP_DUP, nil, 1}, {OP_HASH160, nil, 2},
			{OP_DATA_20, mustParseShortForm("0x01{20}"), 23},
			{OP_EQUAL, nil, 24}, {OP_CHECKSIG, nil, 25},
		},
		finalIdx: 25,
		err:      nil,
	}, {
		name:   "almost pay-to-pubkey-hash (short data)",
		script: mustParseShortForm("DUP HASH160 DATA_20 0x01{17} EQUAL CHECKSIG"),
		expected: []expectedResult{
			{OP_DUP, nil, 1}, {OP_HASH160, nil, 2},
		},
		finalIdx: 2,
		err:      scriptError(ErrMalformedPush, ""),
	}, {
		name:   "almost pay-to-pubkey-hash (overlapped data)",
		script: mustParseShortForm("DUP HASH160 DATA_20 0x01{19} EQUAL CHECKSIG"),
		expected: []expectedResult{
			{OP_DUP, nil, 1}, {OP_HASH160, nil, 2},
			{OP_DATA_20, mustParseShortForm("0x01{19} EQUAL"), 23},
			{OP_CHECKSIG, nil, 24},
		},
		finalIdx: 24,
		err:      nil,
	}, {
		name:   "pay-to-script-hash",
		script: mustParseShortForm("HASH160 DATA_20 0x01{20} EQUAL"),
		expected: []expectedResult{
			{OP_HASH160, nil, 1},
			{OP_DATA_20, mustParseShortForm("0x01{20}"), 22},
			{OP_EQUAL, nil, 23},
		},
		finalIdx: 23,
		err:      nil,
	}, {
		name:   "almost pay-to-script-hash (short data)",
		script: mustParseShortForm("HASH160 DATA_20 0x01{18} EQUAL"),
		expected: []expectedResult{
			{OP_HASH160, nil, 1},
		},
		finalIdx: 1,
		err:      scriptError(ErrMalformedPush, ""),
	}, {
		name:   "almost pay-to-script-hash (overlapped data)",
		script: mustParseShortForm("HASH160 DATA_20 0x01{19} EQUAL"),
		expected: []expectedResult{
			{OP_HASH160, nil, 1},
			{OP_DATA_20, mustParseShortForm("0x01{19} EQUAL"), 22},
		},
		finalIdx: 22,
		err:      nil,
	}}...)

	const scriptVersion = 0
	for _, test := range tests {
		tokenizer := MakeScriptTokenizer(scriptVersion, test.script)
		var opcodeNum int
		for tokenizer.Next() {
			// 确保当存在错误集时 Next 永远不会返回 true。
			if err := tokenizer.Err(); err != nil {
				t.Fatalf("%q: Next returned true when tokenizer has err: %v",
					test.name, err)
			}

			// 确保测试数据需要解析令牌。
			op := tokenizer.Opcode()
			data := tokenizer.Data()
			if opcodeNum >= len(test.expected) {
				t.Fatalf("%q: unexpected token '%d' (data: '%x')", test.name,
					op, data)
			}
			expected := &test.expected[opcodeNum]

			// 确保操作码和数据是预期值。
			if op != expected.op {
				t.Fatalf("%q: unexpected opcode -- got %v, want %v", test.name,
					op, expected.op)
			}
			if !bytes.Equal(data, expected.data) {
				t.Fatalf("%q: unexpected data -- got %x, want %x", test.name,
					data, expected.data)
			}

			tokenizerIdx := tokenizer.ByteIndex()
			if tokenizerIdx != expected.index {
				t.Fatalf("%q: unexpected byte index -- got %d, want %d",
					test.name, tokenizerIdx, expected.index)
			}

			opcodeNum++
		}

		// 确保标记生成器声称已完成。 无论是否存在解析错误，情况都应该如此。
		if !tokenizer.Done() {
			t.Fatalf("%q: tokenizer claims it is not done", test.name)
		}

		// 确保错误符合预期。
		if test.err == nil && tokenizer.Err() != nil {
			t.Fatalf("%q: unexpected tokenizer err -- got %v, want nil",
				test.name, tokenizer.Err())
		} else if test.err != nil {
			if !IsErrorCode(tokenizer.Err(), test.err.(Error).ErrorCode) {
				t.Fatalf("%q: unexpected tokenizer err -- got %v, want %v",
					test.name, tokenizer.Err(), test.err.(Error).ErrorCode)
			}
		}

		// 确保最终的指标是期望值。
		tokenizerIdx := tokenizer.ByteIndex()
		if tokenizerIdx != test.finalIdx {
			t.Fatalf("%q: unexpected final byte index -- got %d, want %d",
				test.name, tokenizerIdx, test.finalIdx)
		}
	}
}

// TestScriptTokenizerUnsupportedVersion 确保标记生成器因脚本版本不受支持而立即失败。
func TestScriptTokenizerUnsupportedVersion(t *testing.T) {
	const scriptVersion = 65535
	tokenizer := MakeScriptTokenizer(scriptVersion, nil)
	if !IsErrorCode(tokenizer.Err(), ErrUnsupportedScriptVersion) {
		t.Fatalf("script tokenizer did not error with unsupported version")
	}
}
