// 包含测试脚本处理功能的代码。

package txscript

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/wire"
)

// TestPushedData 确保 PushedData 函数从各种脚本中提取预期数据。
func TestPushedData(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		script string
		out    [][]byte
		valid  bool
	}{
		{
			"0 IF 0 ELSE 2 ENDIF",
			[][]byte{nil, nil},
			true,
		},
		{
			"16777216 10000000",
			[][]byte{
				{0x00, 0x00, 0x00, 0x01}, // 16777216
				{0x80, 0x96, 0x98, 0x00}, // 10000000
			},
			true,
		},
		{
			"DUP HASH160 '17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem' EQUALVERIFY CHECKSIG",
			[][]byte{
				// 17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem
				{
					0x31, 0x37, 0x56, 0x5a, 0x4e, 0x58, 0x31, 0x53, 0x4e, 0x35,
					0x4e, 0x74, 0x4b, 0x61, 0x38, 0x55, 0x51, 0x46, 0x78, 0x77,
					0x51, 0x62, 0x46, 0x65, 0x46, 0x63, 0x33, 0x69, 0x71, 0x52,
					0x59, 0x68, 0x65, 0x6d,
				},
			},
			true,
		},
		{
			"PUSHDATA4 1000 EQUAL",
			nil,
			false,
		},
	}

	for i, test := range tests {
		script := mustParseShortForm(test.script)
		data, err := PushedData(script)
		if test.valid && err != nil {
			t.Errorf("TestPushedData failed test #%d: %v\n", i, err)
			continue
		} else if !test.valid && err == nil {
			t.Errorf("TestPushedData failed test #%d: test should "+
				"be invalid\n", i)
			continue
		}
		if !reflect.DeepEqual(data, test.out) {
			t.Errorf("TestPushedData failed test #%d: want: %x "+
				"got: %x\n", i, test.out, data)
		}
	}
}

// TestHasCanonicalPush 确保 isCanonicalPush 函数按预期工作。
func TestHasCanonicalPush(t *testing.T) {
	t.Parallel()

	const scriptVersion = 0
	for i := 0; i < 65535; i++ {
		script, err := NewScriptBuilder().AddInt64(int64(i)).Script()
		if err != nil {
			t.Errorf("Script: test #%d unexpected error: %v\n", i, err)
			continue
		}
		if !IsPushOnlyScript(script) {
			t.Errorf("IsPushOnlyScript: test #%d failed: %x\n", i, script)
			continue
		}
		tokenizer := MakeScriptTokenizer(scriptVersion, script)
		for tokenizer.Next() {
			if !isCanonicalPush(tokenizer.Opcode(), tokenizer.Data()) {
				t.Errorf("isCanonicalPush: test #%d failed: %x\n", i, script)
				break
			}
		}
	}
	for i := 0; i <= MaxScriptElementSize; i++ {
		builder := NewScriptBuilder()
		builder.AddData(bytes.Repeat([]byte{0x49}, i))
		script, err := builder.Script()
		if err != nil {
			t.Errorf("Script: test #%d unexpected error: %v\n", i, err)
			continue
		}
		if !IsPushOnlyScript(script) {
			t.Errorf("IsPushOnlyScript: test #%d failed: %x\n", i, script)
			continue
		}
		tokenizer := MakeScriptTokenizer(scriptVersion, script)
		for tokenizer.Next() {
			if !isCanonicalPush(tokenizer.Opcode(), tokenizer.Data()) {
				t.Errorf("isCanonicalPush: test #%d failed: %x\n", i, script)
				break
			}
		}
	}
}

// TestGetPreciseSigOps 确保更精确的签名操作计数机制（包括 P2SH 脚本中的签名）按预期工作。
func TestGetPreciseSigOps(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		scriptSig []byte
		nSigOps   int
	}{
		{
			name:      "scriptSig doesn't parse",
			scriptSig: mustParseShortForm("PUSHDATA1 0x02"),
		},
		{
			name:      "scriptSig isn't push only",
			scriptSig: mustParseShortForm("1 DUP"),
			nSigOps:   0,
		},
		{
			name:      "scriptSig length 0",
			scriptSig: nil,
			nSigOps:   0,
		},
		{
			name: "No script at the end",
			// 最后没有脚本，但仍然只推送。
			scriptSig: mustParseShortForm("1 1"),
			nSigOps:   0,
		},
		{
			name:      "pushed script doesn't parse",
			scriptSig: mustParseShortForm("DATA_2 PUSHDATA1 0x02"),
		},
	}

	// p2sh 脚本中的签名对于测试来说是无意义的，因为该脚本永远不会被执行。 重要的是它与正确的模式相匹配。
	pkScript := mustParseShortForm("HASH160 DATA_20 0x433ec2ac1ffa1b7b7d0" +
		"27f564529c57197f9ae88 EQUAL")
	for _, test := range tests {
		count := GetPreciseSigOpCount(test.scriptSig, pkScript, true)
		if count != test.nSigOps {
			t.Errorf("%s: expected count of %d, got %d", test.name,
				test.nSigOps, count)

		}
	}
}

// TestGetWitnessSigOpCount 测试 p2wkh、p2wsh、嵌套 p2sh 和无效变体的 sig op 计数是否正确计数。
func TestGetWitnessSigOpCount(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string

		sigScript []byte
		pkScript  []byte
		witness   wire.TxWitness

		numSigOps int
	}{
		// 定期的 p2wkh 见证计划。 所花费的输出应该只计算一个 sig-op。
		{
			name: "p2wkh",
			pkScript: mustParseShortForm("OP_0 DATA_20 " +
				"0x365ab47888e150ff46f8d51bce36dcd680f1283f"),
			witness: wire.TxWitness{
				hexToBytes("3045022100ee9fe8f9487afa977" +
					"6647ebcf0883ce0cd37454d7ce19889d34ba2c9" +
					"9ce5a9f402200341cb469d0efd3955acb9e46" +
					"f568d7e2cc10f9084aaff94ced6dc50a59134ad01"),
				hexToBytes("03f0000d0639a22bfaf217e4c9428" +
					"9c2b0cc7fa1036f7fd5d9f61a9d6ec153100e"),
			},
			numSigOps: 1,
		},
		// 嵌套在 p2sh 输出脚本中的 p2wkh 见证程序。
		// 该模式应该被正确识别并且仅属性为单个 sig 操作。
		{
			name: "nested p2sh",
			sigScript: hexToBytes("160014ad0ffa2e387f07" +
				"e7ead14dc56d5a97dbd6ff5a23"),
			pkScript: mustParseShortForm("HASH160 DATA_20 " +
				"0xb3a84b564602a9d68b4c9f19c2ea61458ff7826c EQUAL"),
			witness: wire.TxWitness{
				hexToBytes("3045022100cb1c2ac1ff1d57d" +
					"db98f7bdead905f8bf5bcc8641b029ce8eef25" +
					"c75a9e22a4702203be621b5c86b771288706be5" +
					"a7eee1db4fceabf9afb7583c1cc6ee3f8297b21201"),
				hexToBytes("03f0000d0639a22bfaf217e4c9" +
					"4289c2b0cc7fa1036f7fd5d9f61a9d6ec153100e"),
			},
			numSigOps: 1,
		},
		// 一个 p2sh 脚本，使用 2-of-2 多重签名输出。
		{
			name:      "p2wsh multi-sig spend",
			numSigOps: 2,
			pkScript: hexToBytes("0020e112b88a0cd87ba387f" +
				"449d443ee2596eb353beb1f0351ab2cba8909d875db23"),
			witness: wire.TxWitness{
				hexToBytes("522103b05faca7ceda92b493" +
					"3f7acdf874a93de0dc7edc461832031cd69cbb1d1e" +
					"6fae2102e39092e031c1621c902e3704424e8d8" +
					"3ca481d4d4eeae1b7970f51c78231207e52ae"),
			},
		},
		// p2wsh 见证程序。 但是，见证脚本无法解析脚本的有效部分。 因此，脚本的有效部分仍应被计算在内。
		{
			name:      "witness script doesn't parse",
			numSigOps: 1,
			pkScript: hexToBytes("0020e112b88a0cd87ba387f44" +
				"9d443ee2596eb353beb1f0351ab2cba8909d875db23"),
			witness: wire.TxWitness{
				mustParseShortForm("DUP HASH160 " +
					"'17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem'" +
					" EQUALVERIFY CHECKSIG DATA_20 0x91"),
			},
		},
	}

	for _, test := range tests {
		count := GetWitnessSigOpCount(test.sigScript, test.pkScript,
			test.witness)
		if count != test.numSigOps {
			t.Errorf("%s: expected count of %d, got %d", test.name,
				test.numSigOps, count)

		}
	}
}

// TestRemoveOpcodes 确保从脚本中删除操作码的行为符合预期。
func TestRemoveOpcodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		before string
		remove byte
		err    error
		after  string
	}{
		{
			// 没有什么可删除的。
			name:   "nothing to remove",
			before: "NOP",
			remove: OP_CODESEPARATOR,
			after:  "NOP",
		},
		{
			// 测试基本操作码删除。
			name:   "codeseparator 1",
			before: "NOP CODESEPARATOR TRUE",
			remove: OP_CODESEPARATOR,
			after:  "NOP TRUE",
		},
		{
			// 所讨论的操作码实际上是先前操作码中数据的一部分。
			name:   "codeseparator by coincidence",
			before: "NOP DATA_1 CODESEPARATOR TRUE",
			remove: OP_CODESEPARATOR,
			after:  "NOP DATA_1 CODESEPARATOR TRUE",
		},
		{
			name:   "invalid opcode",
			before: "CAT",
			remove: OP_CODESEPARATOR,
			after:  "CAT",
		},
		{
			name:   "invalid length (instruction)",
			before: "PUSHDATA1",
			remove: OP_CODESEPARATOR,
			err:    scriptError(ErrMalformedPush, ""),
		},
		{
			name:   "invalid length (data)",
			before: "PUSHDATA1 0xff 0xfe",
			remove: OP_CODESEPARATOR,
			err:    scriptError(ErrMalformedPush, ""),
		},
	}

	// tstRemoveOpcode 是一个方便的函数，用于解析提供的原始脚本，删除传递的操作码，然后将结果解析回原始脚本。
	const scriptVersion = 0
	tstRemoveOpcode := func(script []byte, opcode byte) ([]byte, error) {
		if err := checkScriptParses(scriptVersion, script); err != nil {
			return nil, err
		}
		return removeOpcodeRaw(script, opcode), nil
	}

	for _, test := range tests {
		before := mustParseShortForm(test.before)
		after := mustParseShortForm(test.after)
		result, err := tstRemoveOpcode(before, test.remove)
		if e := tstCheckScriptError(err, test.err); e != nil {
			t.Errorf("%s: %v", test.name, e)
			continue
		}

		if !bytes.Equal(after, result) {
			t.Errorf("%s: value does not equal expected: exp: %q"+
				" got: %q", test.name, after, result)
		}
	}
}

// TestRemoveOpcodeByData 确保根据数据包含的数据删除携带操作码的数据按预期工作。
func TestRemoveOpcodeByData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		before []byte
		remove []byte
		err    error
		after  []byte
	}{
		{
			name:   "nothing to do",
			before: []byte{OP_NOP},
			remove: []byte{1, 2, 3, 4},
			after:  []byte{OP_NOP},
		},
		{
			name:   "simple case",
			before: []byte{OP_DATA_4, 1, 2, 3, 4},
			remove: []byte{1, 2, 3, 4},
			after:  nil,
		},
		{
			name:   "simple case (miss)",
			before: []byte{OP_DATA_4, 1, 2, 3, 4},
			remove: []byte{1, 2, 3, 5},
			after:  []byte{OP_DATA_4, 1, 2, 3, 4},
		},
		{
			// 填充以保持规范。
			name: "simple case (pushdata1)",
			before: append(append([]byte{OP_PUSHDATA1, 76},
				bytes.Repeat([]byte{0}, 72)...),
				[]byte{1, 2, 3, 4}...),
			remove: []byte{1, 2, 3, 4},
			after:  nil,
		},
		{
			name: "simple case (pushdata1 miss)",
			before: append(append([]byte{OP_PUSHDATA1, 76},
				bytes.Repeat([]byte{0}, 72)...),
				[]byte{1, 2, 3, 4}...),
			remove: []byte{1, 2, 3, 5},
			after: append(append([]byte{OP_PUSHDATA1, 76},
				bytes.Repeat([]byte{0}, 72)...),
				[]byte{1, 2, 3, 4}...),
		},
		{
			name:   "simple case (pushdata1 miss noncanonical)",
			before: []byte{OP_PUSHDATA1, 4, 1, 2, 3, 4},
			remove: []byte{1, 2, 3, 4},
			after:  []byte{OP_PUSHDATA1, 4, 1, 2, 3, 4},
		},
		{
			name: "simple case (pushdata2)",
			before: append(append([]byte{OP_PUSHDATA2, 0, 1},
				bytes.Repeat([]byte{0}, 252)...),
				[]byte{1, 2, 3, 4}...),
			remove: []byte{1, 2, 3, 4},
			after:  nil,
		},
		{
			name: "simple case (pushdata2 miss)",
			before: append(append([]byte{OP_PUSHDATA2, 0, 1},
				bytes.Repeat([]byte{0}, 252)...),
				[]byte{1, 2, 3, 4}...),
			remove: []byte{1, 2, 3, 4, 5},
			after: append(append([]byte{OP_PUSHDATA2, 0, 1},
				bytes.Repeat([]byte{0}, 252)...),
				[]byte{1, 2, 3, 4}...),
		},
		{
			name:   "simple case (pushdata2 miss noncanonical)",
			before: []byte{OP_PUSHDATA2, 4, 0, 1, 2, 3, 4},
			remove: []byte{1, 2, 3, 4},
			after:  []byte{OP_PUSHDATA2, 4, 0, 1, 2, 3, 4},
		},
		{
			// 这是为了使推送规范化而进行填充的。
			name: "simple case (pushdata4)",
			before: append(append([]byte{OP_PUSHDATA4, 0, 0, 1, 0},
				bytes.Repeat([]byte{0}, 65532)...),
				[]byte{1, 2, 3, 4}...),
			remove: []byte{1, 2, 3, 4},
			after:  nil,
		},
		{
			name:   "simple case (pushdata4 miss noncanonical)",
			before: []byte{OP_PUSHDATA4, 4, 0, 0, 0, 1, 2, 3, 4},
			remove: []byte{1, 2, 3, 4},
			after:  []byte{OP_PUSHDATA4, 4, 0, 0, 0, 1, 2, 3, 4},
		},
		{
			// 这是为了使推送规范化而进行填充的。
			name: "simple case (pushdata4 miss)",
			before: append(append([]byte{OP_PUSHDATA4, 0, 0, 1, 0},
				bytes.Repeat([]byte{0}, 65532)...), []byte{1, 2, 3, 4}...),
			remove: []byte{1, 2, 3, 4, 5},
			after: append(append([]byte{OP_PUSHDATA4, 0, 0, 1, 0},
				bytes.Repeat([]byte{0}, 65532)...), []byte{1, 2, 3, 4}...),
		},
		{
			name:   "invalid opcode ",
			before: []byte{OP_UNKNOWN187},
			remove: []byte{1, 2, 3, 4},
			after:  []byte{OP_UNKNOWN187},
		},
		{
			name:   "invalid length (instruction)",
			before: []byte{OP_PUSHDATA1},
			remove: []byte{1, 2, 3, 4},
			err:    scriptError(ErrMalformedPush, ""),
		},
		{
			name:   "invalid length (data)",
			before: []byte{OP_PUSHDATA1, 255, 254},
			remove: []byte{1, 2, 3, 4},
			err:    scriptError(ErrMalformedPush, ""),
		},
	}

	// tstRemoveOpcodeByData 是一个便利函数，可确保在尝试删除传递的数据之前解析提供的脚本。
	const scriptVersion = 0
	tstRemoveOpcodeByData := func(script []byte, data []byte) ([]byte, error) {
		if err := checkScriptParses(scriptVersion, script); err != nil {
			return nil, err
		}

		return removeOpcodeByData(script, data), nil
	}

	for _, test := range tests {
		result, err := tstRemoveOpcodeByData(test.before, test.remove)
		if e := tstCheckScriptError(err, test.err); e != nil {
			t.Errorf("%s: %v", test.name, e)
			continue
		}

		if !bytes.Equal(test.after, result) {
			t.Errorf("%s: value does not equal expected: exp: %q"+
				" got: %q", test.name, test.after, result)
		}
	}
}

// TestIsPayToScriptHash 确保 IsPayToScriptHash 函数返回 scriptClassTests 中所有脚本的预期结果。
func TestIsPayToScriptHash(t *testing.T) {
	t.Parallel()

	for _, test := range scriptClassTests {
		script := mustParseShortForm(test.script)
		shouldBe := (test.class == ScriptHashTy)
		p2sh := IsPayToScriptHash(script)
		if p2sh != shouldBe {
			t.Errorf("%s: expected p2sh %v, got %v", test.name,
				shouldBe, p2sh)
		}
	}
}

// TestIsPayToWitnessScriptHash 确保 IsPayToWitnessScriptHash 函数返回 scriptClassTests 中所有脚本的预期结果。
func TestIsPayToWitnessScriptHash(t *testing.T) {
	t.Parallel()

	for _, test := range scriptClassTests {
		script := mustParseShortForm(test.script)
		shouldBe := (test.class == WitnessV0ScriptHashTy)
		p2wsh := IsPayToWitnessScriptHash(script)
		if p2wsh != shouldBe {
			t.Errorf("%s: expected p2wsh %v, got %v", test.name,
				shouldBe, p2wsh)
		}
	}
}

// TestIsPayToWitnessPubKeyHash 确保 IsPayToWitnessPubKeyHash 函数返回 scriptClassTests 中所有脚本的预期结果。
func TestIsPayToWitnessPubKeyHash(t *testing.T) {
	t.Parallel()

	for _, test := range scriptClassTests {
		script := mustParseShortForm(test.script)
		shouldBe := (test.class == WitnessV0PubKeyHashTy)
		p2wkh := IsPayToWitnessPubKeyHash(script)
		if p2wkh != shouldBe {
			t.Errorf("%s: expected p2wkh %v, got %v", test.name,
				shouldBe, p2wkh)
		}
	}
}

// TestHasCanonicalPushes 确保 isCanonicalPush 函数正确确定出于removeOpcodeByData 目的什么被视为规范推送。
func TestHasCanonicalPushes(t *testing.T) {
	t.Parallel()

	const scriptVersion = 0
	tests := []struct {
		name     string
		script   string
		expected bool
	}{
		{
			name: "does not parse",
			script: "0x046708afdb0fe5548271967f1a67130b7105cd6a82" +
				"8e03909a67962e0ea1f61d",
			expected: false,
		},
		{
			name:     "non-canonical push",
			script:   "PUSHDATA1 0x04 0x01020304",
			expected: false,
		},
	}

	for _, test := range tests {
		script := mustParseShortForm(test.script)
		if err := checkScriptParses(scriptVersion, script); err != nil {
			if test.expected {
				t.Errorf("%q: script parse failed: %v", test.name, err)
			}
			continue
		}
		tokenizer := MakeScriptTokenizer(scriptVersion, script)
		for tokenizer.Next() {
			result := isCanonicalPush(tokenizer.Opcode(), tokenizer.Data())
			if result != test.expected {
				t.Errorf("%q: isCanonicalPush wrong result\ngot: %v\nwant: %v",
					test.name, result, test.expected)
				break
			}
		}
	}
}

// TestIsPushOnlyScript 确保 IsPushOnlyScript 函数返回预期结果。
func TestIsPushOnlyScript(t *testing.T) {
	t.Parallel()

	test := struct {
		name     string
		script   []byte
		expected bool
	}{
		name: "does not parse",
		script: mustParseShortForm("0x046708afdb0fe5548271967f1a67130" +
			"b7105cd6a828e03909a67962e0ea1f61d"),
		expected: false,
	}

	if IsPushOnlyScript(test.script) != test.expected {
		t.Errorf("IsPushOnlyScript (%s) wrong result\ngot: %v\nwant: "+
			"%v", test.name, true, test.expected)
	}
}

// TestIsUnspendable 确保 IsUnspendable 函数返回预期结果。
func TestIsUnspendable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pkScript []byte
		expected bool
	}{
		{
			// 花不完的
			pkScript: []byte{0x6a, 0x04, 0x74, 0x65, 0x73, 0x74},
			expected: true,
		},
		{
			// 可消费的
			pkScript: []byte{0x76, 0xa9, 0x14, 0x29, 0x95, 0xa0,
				0xfe, 0x68, 0x43, 0xfa, 0x9b, 0x95, 0x45,
				0x97, 0xf0, 0xdc, 0xa7, 0xa4, 0x4d, 0xf6,
				0xfa, 0x0b, 0x5c, 0x88, 0xac},
			expected: false,
		},
		{
			// 可消费的
			pkScript: []byte{0xa9, 0x14, 0x82, 0x1d, 0xba, 0x94, 0xbc, 0xfb,
				0xa2, 0x57, 0x36, 0xa3, 0x9e, 0x5d, 0x14, 0x5d, 0x69, 0x75,
				0xba, 0x8c, 0x0b, 0x42, 0x87},
			expected: false,
		},
		{
			// 不一定是不花钱的
			pkScript: []byte{},
			expected: false,
		},
		{
			// 可消费的
			pkScript: []byte{OP_TRUE},
			expected: false,
		},
		{
			// 花不完的
			pkScript: []byte{OP_RETURN},
			expected: true,
		},
	}

	for i, test := range tests {
		res := IsUnspendable(test.pkScript)
		if res != test.expected {
			t.Errorf("TestIsUnspendable #%d failed: got %v want %v",
				i, res, test.expected)
			continue
		}
	}
}
