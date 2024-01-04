// 包含测试脚本构建器的代码。

package txscript

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestScriptBuilderAlloc 测试通过 NewScriptBuilder 函数对脚本进行的预分配是否按预期工作。
func TestScriptBuilderAlloc(t *testing.T) {
	// 使用默认值，我们应该得到一个容量为 500 字节的脚本，这对于大多数脚本来说相当大。
	defaultBuilder := NewScriptBuilder()
	require.EqualValues(t, defaultScriptAlloc, cap(defaultBuilder.script))

	const allocSize = 23
	builder := NewScriptBuilder(WithScriptAllocSize(allocSize))

	// 脚本的初始容量应设置为显式值。
	require.EqualValues(t, allocSize, cap(builder.script))

	builder.AddOp(OP_HASH160)
	builder.AddData(make([]byte, 20))
	builder.AddOp(OP_EQUAL)
	script, err := builder.Script()
	require.NoError(t, err)

	require.Len(t, script, allocSize)

	// 容量不应该改变，因为脚本应该已经适合了。
	require.EqualValues(t, allocSize, cap(builder.script))
}

// TestScriptBuilderAddOp 测试通过 ScriptBuilder API 将操作码推送到脚本是否按预期工作。
func TestScriptBuilderAddOp(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opcodes  []byte
		expected []byte
	}{
		{
			name:     "push OP_0",
			opcodes:  []byte{OP_0},
			expected: []byte{OP_0},
		},
		{
			name:     "push OP_1 OP_2",
			opcodes:  []byte{OP_1, OP_2},
			expected: []byte{OP_1, OP_2},
		},
		{
			name:     "push OP_HASH160 OP_EQUAL",
			opcodes:  []byte{OP_HASH160, OP_EQUAL},
			expected: []byte{OP_HASH160, OP_EQUAL},
		},
	}

	// 运行测试并通过 AddOp 单独添加每个操作。
	builder := NewScriptBuilder()
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		builder.Reset()
		for _, opcode := range test.opcodes {
			builder.AddOp(opcode)
		}
		result, err := builder.Script()
		if err != nil {
			t.Errorf("ScriptBuilder.AddOp #%d (%s) unexpected "+
				"error: %v", i, test.name, err)
			continue
		}
		if !bytes.Equal(result, test.expected) {
			t.Errorf("ScriptBuilder.AddOp #%d (%s) wrong result\n"+
				"got: %x\nwant: %x", i, test.name, result,
				test.expected)
			continue
		}
	}

	// 运行测试并通过 AddOps 批量添加操作。
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		builder.Reset()
		result, err := builder.AddOps(test.opcodes).Script()
		if err != nil {
			t.Errorf("ScriptBuilder.AddOps #%d (%s) unexpected "+
				"error: %v", i, test.name, err)
			continue
		}
		if !bytes.Equal(result, test.expected) {
			t.Errorf("ScriptBuilder.AddOps #%d (%s) wrong result\n"+
				"got: %x\nwant: %x", i, test.name, result,
				test.expected)
			continue
		}
	}

}

// TestScriptBuilderAddInt64 测试通过 ScriptBuilder API 将有符号整数推送到脚本是否按预期工作。
func TestScriptBuilderAddInt64(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		val      int64
		expected []byte
	}{
		{name: "push -1", val: -1, expected: []byte{OP_1NEGATE}},
		{name: "push small int 0", val: 0, expected: []byte{OP_0}},
		{name: "push small int 1", val: 1, expected: []byte{OP_1}},
		{name: "push small int 2", val: 2, expected: []byte{OP_2}},
		{name: "push small int 3", val: 3, expected: []byte{OP_3}},
		{name: "push small int 4", val: 4, expected: []byte{OP_4}},
		{name: "push small int 5", val: 5, expected: []byte{OP_5}},
		{name: "push small int 6", val: 6, expected: []byte{OP_6}},
		{name: "push small int 7", val: 7, expected: []byte{OP_7}},
		{name: "push small int 8", val: 8, expected: []byte{OP_8}},
		{name: "push small int 9", val: 9, expected: []byte{OP_9}},
		{name: "push small int 10", val: 10, expected: []byte{OP_10}},
		{name: "push small int 11", val: 11, expected: []byte{OP_11}},
		{name: "push small int 12", val: 12, expected: []byte{OP_12}},
		{name: "push small int 13", val: 13, expected: []byte{OP_13}},
		{name: "push small int 14", val: 14, expected: []byte{OP_14}},
		{name: "push small int 15", val: 15, expected: []byte{OP_15}},
		{name: "push small int 16", val: 16, expected: []byte{OP_16}},
		{name: "push 17", val: 17, expected: []byte{OP_DATA_1, 0x11}},
		{name: "push 65", val: 65, expected: []byte{OP_DATA_1, 0x41}},
		{name: "push 127", val: 127, expected: []byte{OP_DATA_1, 0x7f}},
		{name: "push 128", val: 128, expected: []byte{OP_DATA_2, 0x80, 0}},
		{name: "push 255", val: 255, expected: []byte{OP_DATA_2, 0xff, 0}},
		{name: "push 256", val: 256, expected: []byte{OP_DATA_2, 0, 0x01}},
		{name: "push 32767", val: 32767, expected: []byte{OP_DATA_2, 0xff, 0x7f}},
		{name: "push 32768", val: 32768, expected: []byte{OP_DATA_3, 0, 0x80, 0}},
		{name: "push -2", val: -2, expected: []byte{OP_DATA_1, 0x82}},
		{name: "push -3", val: -3, expected: []byte{OP_DATA_1, 0x83}},
		{name: "push -4", val: -4, expected: []byte{OP_DATA_1, 0x84}},
		{name: "push -5", val: -5, expected: []byte{OP_DATA_1, 0x85}},
		{name: "push -17", val: -17, expected: []byte{OP_DATA_1, 0x91}},
		{name: "push -65", val: -65, expected: []byte{OP_DATA_1, 0xc1}},
		{name: "push -127", val: -127, expected: []byte{OP_DATA_1, 0xff}},
		{name: "push -128", val: -128, expected: []byte{OP_DATA_2, 0x80, 0x80}},
		{name: "push -255", val: -255, expected: []byte{OP_DATA_2, 0xff, 0x80}},
		{name: "push -256", val: -256, expected: []byte{OP_DATA_2, 0x00, 0x81}},
		{name: "push -32767", val: -32767, expected: []byte{OP_DATA_2, 0xff, 0xff}},
		{name: "push -32768", val: -32768, expected: []byte{OP_DATA_3, 0x00, 0x80, 0x80}},
	}

	builder := NewScriptBuilder()
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		builder.Reset().AddInt64(test.val)
		result, err := builder.Script()
		if err != nil {
			t.Errorf("ScriptBuilder.AddInt64 #%d (%s) unexpected "+
				"error: %v", i, test.name, err)
			continue
		}
		if !bytes.Equal(result, test.expected) {
			t.Errorf("ScriptBuilder.AddInt64 #%d (%s) wrong result\n"+
				"got: %x\nwant: %x", i, test.name, result,
				test.expected)
			continue
		}
	}
}

// TestScriptBuilderAddData 测试通过 ScriptBuilder API 将数据推送到脚本是否按预期工作并符合 BIP0062。
func TestScriptBuilderAddData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     []byte
		expected []byte
		useFull  bool // 使用 AddFullData 而不是 AddData。
	}{
		// BIP0062: 推送空字节序列必须使用 OP_0。
		{name: "push empty byte sequence", data: nil, expected: []byte{OP_0}},
		{name: "push 1 byte 0x00", data: []byte{0x00}, expected: []byte{OP_0}},

		// BIP0062: 推送字节 0x01 到 0x10 的 1 字节序列必须使用 OP_n。
		{name: "push 1 byte 0x01", data: []byte{0x01}, expected: []byte{OP_1}},
		{name: "push 1 byte 0x02", data: []byte{0x02}, expected: []byte{OP_2}},
		{name: "push 1 byte 0x03", data: []byte{0x03}, expected: []byte{OP_3}},
		{name: "push 1 byte 0x04", data: []byte{0x04}, expected: []byte{OP_4}},
		{name: "push 1 byte 0x05", data: []byte{0x05}, expected: []byte{OP_5}},
		{name: "push 1 byte 0x06", data: []byte{0x06}, expected: []byte{OP_6}},
		{name: "push 1 byte 0x07", data: []byte{0x07}, expected: []byte{OP_7}},
		{name: "push 1 byte 0x08", data: []byte{0x08}, expected: []byte{OP_8}},
		{name: "push 1 byte 0x09", data: []byte{0x09}, expected: []byte{OP_9}},
		{name: "push 1 byte 0x0a", data: []byte{0x0a}, expected: []byte{OP_10}},
		{name: "push 1 byte 0x0b", data: []byte{0x0b}, expected: []byte{OP_11}},
		{name: "push 1 byte 0x0c", data: []byte{0x0c}, expected: []byte{OP_12}},
		{name: "push 1 byte 0x0d", data: []byte{0x0d}, expected: []byte{OP_13}},
		{name: "push 1 byte 0x0e", data: []byte{0x0e}, expected: []byte{OP_14}},
		{name: "push 1 byte 0x0f", data: []byte{0x0f}, expected: []byte{OP_15}},
		{name: "push 1 byte 0x10", data: []byte{0x10}, expected: []byte{OP_16}},

		// BIP0062: 推送字节 0x81 必须使用 OP_1NEGATE。
		{name: "push 1 byte 0x81", data: []byte{0x81}, expected: []byte{OP_1NEGATE}},

		// BIP0062: 将任何其他字节序列推送到 75 个字节必须使用正常数据推送（操作码字节 n，其中 n 是字节数，后面是要推送的 n 个字节的数据）。
		{name: "push 1 byte 0x11", data: []byte{0x11}, expected: []byte{OP_DATA_1, 0x11}},
		{name: "push 1 byte 0x80", data: []byte{0x80}, expected: []byte{OP_DATA_1, 0x80}},
		{name: "push 1 byte 0x82", data: []byte{0x82}, expected: []byte{OP_DATA_1, 0x82}},
		{name: "push 1 byte 0xff", data: []byte{0xff}, expected: []byte{OP_DATA_1, 0xff}},
		{
			name:     "push data len 17",
			data:     bytes.Repeat([]byte{0x49}, 17),
			expected: append([]byte{OP_DATA_17}, bytes.Repeat([]byte{0x49}, 17)...),
		},
		{
			name:     "push data len 75",
			data:     bytes.Repeat([]byte{0x49}, 75),
			expected: append([]byte{OP_DATA_75}, bytes.Repeat([]byte{0x49}, 75)...),
		},

		// BIP0062: 推送 76 到 255 字节必须使用 OP_PUSHDATA1。
		{
			name:     "push data len 76",
			data:     bytes.Repeat([]byte{0x49}, 76),
			expected: append([]byte{OP_PUSHDATA1, 76}, bytes.Repeat([]byte{0x49}, 76)...),
		},
		{
			name:     "push data len 255",
			data:     bytes.Repeat([]byte{0x49}, 255),
			expected: append([]byte{OP_PUSHDATA1, 255}, bytes.Repeat([]byte{0x49}, 255)...),
		},

		// BIP0062: 推送 256 到 520 字节必须使用 OP_PUSHDATA2。
		{
			name:     "push data len 256",
			data:     bytes.Repeat([]byte{0x49}, 256),
			expected: append([]byte{OP_PUSHDATA2, 0, 1}, bytes.Repeat([]byte{0x49}, 256)...),
		},
		{
			name:     "push data len 520",
			data:     bytes.Repeat([]byte{0x49}, 520),
			expected: append([]byte{OP_PUSHDATA2, 0x08, 0x02}, bytes.Repeat([]byte{0x49}, 520)...),
		},

		// BIP0062: OP_PUSHDATA4 永远不能使用，因为不允许推送超过 520 字节，而以下操作可以使用其他运算符来完成。
		{
			name:     "push data len 521",
			data:     bytes.Repeat([]byte{0x49}, 521),
			expected: nil,
		},
		{
			name:     "push data len 32767 (canonical)",
			data:     bytes.Repeat([]byte{0x49}, 32767),
			expected: nil,
		},
		{
			name:     "push data len 65536 (canonical)",
			data:     bytes.Repeat([]byte{0x49}, 65536),
			expected: nil,
		},

		// 对 PushFullData 函数的附加测试，故意允许数据推送超出回归测试目的的限制。

		// 通过 OP_PUSHDATA_2 推送 3 字节数据。
		{
			name:     "push data len 32767 (non-canonical)",
			data:     bytes.Repeat([]byte{0x49}, 32767),
			expected: append([]byte{OP_PUSHDATA2, 255, 127}, bytes.Repeat([]byte{0x49}, 32767)...),
			useFull:  true,
		},

		// 通过 OP_PUSHDATA_4 推送 5 字节数据。
		{
			name:     "push data len 65536 (non-canonical)",
			data:     bytes.Repeat([]byte{0x49}, 65536),
			expected: append([]byte{OP_PUSHDATA4, 0, 0, 1, 0}, bytes.Repeat([]byte{0x49}, 65536)...),
			useFull:  true,
		},
	}

	builder := NewScriptBuilder()
	t.Logf("Running %d tests", len(tests))
	for i, test := range tests {
		if !test.useFull {
			builder.Reset().AddData(test.data)
		} else {
			builder.Reset().AddFullData(test.data)
		}
		result, _ := builder.Script()
		if !bytes.Equal(result, test.expected) {
			t.Errorf("ScriptBuilder.AddData #%d (%s) wrong result\n"+
				"got: %x\nwant: %x", i, test.name, result,
				test.expected)
			continue
		}
	}
}

// TestExceedMaxScriptSize 确保可用于向脚本添加数据的所有函数不允许脚本超过允许的最大大小。
func TestExceedMaxScriptSize(t *testing.T) {
	t.Parallel()

	// 首先构建最大大小脚本。
	builder := NewScriptBuilder()
	builder.Reset().AddFullData(make([]byte, MaxScriptSize-3))
	origScript, err := builder.Script()
	if err != nil {
		t.Fatalf("Unexpected error for max size script: %v", err)
	}

	// 确保添加超出脚本最大大小的数据不会添加数据。
	script, err := builder.AddData([]byte{0x00}).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatalf("ScriptBuilder.AddData allowed exceeding max script "+
			"size: %v", len(script))
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddData unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}

	// 确保添加超出脚本最大大小的操作码不会添加数据。
	builder.Reset().AddFullData(make([]byte, MaxScriptSize-3))
	script, err = builder.AddOp(OP_0).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatalf("ScriptBuilder.AddOp unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddOp unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}

	// 确保添加超出脚本最大大小的整数不会添加数据。
	builder.Reset().AddFullData(make([]byte, MaxScriptSize-3))
	script, err = builder.AddInt64(0).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatalf("ScriptBuilder.AddInt64 unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddInt64 unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}
}

// TestErroredScript 确保一旦发生错误，所有可用于向脚本添加数据的函数都不会修改脚本。
func TestErroredScript(t *testing.T) {
	t.Parallel()

	// 首先构建一个接近最大大小的脚本，该脚本有足够的剩余空间来添加每种数据类型而不会出现错误，并强制执行初始错误条件。
	builder := NewScriptBuilder()
	builder.Reset().AddFullData(make([]byte, MaxScriptSize-8))
	origScript, err := builder.Script()
	if err != nil {
		t.Fatalf("ScriptBuilder.AddFullData unexpected error: %v", err)
	}
	script, err := builder.AddData([]byte{0x00, 0x00, 0x00, 0x00, 0x00}).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatalf("ScriptBuilder.AddData allowed exceeding max script "+
			"size: %v", len(script))
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddData unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}

	// 确保向出错的脚本添加数据不会成功，即使使用非规范路径也是如此。
	script, err = builder.AddFullData([]byte{0x00}).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatal("ScriptBuilder.AddFullData succeeded on errored script")
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddFullData unexpected modified "+
			"script - got len %d, want len %d", len(script),
			len(origScript))
	}

	// 确保向出错的脚本添加数据不会成功。
	script, err = builder.AddData([]byte{0x00}).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatal("ScriptBuilder.AddData succeeded on errored script")
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddData unexpected modified "+
			"script - got len %d, want len %d", len(script),
			len(origScript))
	}

	// 确保向出错的脚本添加操作码不会成功。
	script, err = builder.AddOp(OP_0).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatal("ScriptBuilder.AddOp succeeded on errored script")
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddOp unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}

	// 确保向出错的脚本添加整数不会成功。
	script, err = builder.AddInt64(0).Script()
	if _, ok := err.(ErrScriptNotCanonical); !ok || err == nil {
		t.Fatal("ScriptBuilder.AddInt64 succeeded on errored script")
	}
	if !bytes.Equal(script, origScript) {
		t.Fatalf("ScriptBuilder.AddInt64 unexpected modified script - "+
			"got len %d, want len %d", len(script), len(origScript))
	}

	// 确保错误已设置消息。
	if err.Error() == "" {
		t.Fatal("ErrScriptNotCanonical.Error does not have any text")
	}
}
