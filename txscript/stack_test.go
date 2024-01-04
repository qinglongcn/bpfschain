// 包含测试数据栈功能的代码。

package txscript

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

// tstCheckScriptError 确保两个传递的错误的类型相同（要么都是 nil，要么都是 Error 类型），并且当不为 nil 时，它们的错误代码匹配。
func tstCheckScriptError(gotErr, wantErr error) error {
	// 确保错误代码是预期的类型，并且错误代码与测试实例中指定的值匹配。
	if reflect.TypeOf(gotErr) != reflect.TypeOf(wantErr) {
		return fmt.Errorf("wrong error - got %T (%[1]v), want %T",
			gotErr, wantErr)
	}
	if gotErr == nil {
		return nil
	}

	// 确保所需的错误类型是脚本错误。
	werr, ok := wantErr.(Error)
	if !ok {
		return fmt.Errorf("unexpected test error type %T", wantErr)
	}

	// 确保错误代码匹配。 在这里使用原始类型断言是安全的，因为上面的代码已经证明它们是相同的类型，并且想要的错误是脚本错误。
	gotErrorCode := gotErr.(Error).ErrorCode
	if gotErrorCode != werr.ErrorCode {
		return fmt.Errorf("mismatched error code - got %v (%v), want %v",
			gotErrorCode, gotErr, werr.ErrorCode)
	}

	return nil
}

// TestStack 测试所有堆栈操作是否按预期工作。
func TestStack(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		before    [][]byte
		operation func(*stack) error
		err       error
		after     [][]byte
	}{
		{
			"noop",
			[][]byte{{1}, {2}, {3}, {4}, {5}},
			func(s *stack) error {
				return nil
			},
			nil,
			[][]byte{{1}, {2}, {3}, {4}, {5}},
		},
		{
			"peek underflow (byte)",
			[][]byte{{1}, {2}, {3}, {4}, {5}},
			func(s *stack) error {
				_, err := s.PeekByteArray(5)
				return err
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"peek underflow (int)",
			[][]byte{{1}, {2}, {3}, {4}, {5}},
			func(s *stack) error {
				_, err := s.PeekInt(5)
				return err
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"peek underflow (bool)",
			[][]byte{{1}, {2}, {3}, {4}, {5}},
			func(s *stack) error {
				_, err := s.PeekBool(5)
				return err
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"pop",
			[][]byte{{1}, {2}, {3}, {4}, {5}},
			func(s *stack) error {
				val, err := s.PopByteArray()
				if err != nil {
					return err
				}
				if !bytes.Equal(val, []byte{5}) {
					return fmt.Errorf("not equal")
				}
				return err
			},
			nil,
			[][]byte{{1}, {2}, {3}, {4}},
		},
		{
			"pop everything",
			[][]byte{{1}, {2}, {3}, {4}, {5}},
			func(s *stack) error {
				for i := 0; i < 5; i++ {
					_, err := s.PopByteArray()
					if err != nil {
						return err
					}
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"pop underflow",
			[][]byte{{1}, {2}, {3}, {4}, {5}},
			func(s *stack) error {
				for i := 0; i < 6; i++ {
					_, err := s.PopByteArray()
					if err != nil {
						return err
					}
				}
				return nil
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"pop bool",
			[][]byte{nil},
			func(s *stack) error {
				val, err := s.PopBool()
				if err != nil {
					return err
				}

				if val {
					return fmt.Errorf("unexpected value")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"pop bool",
			[][]byte{{1}},
			func(s *stack) error {
				val, err := s.PopBool()
				if err != nil {
					return err
				}

				if !val {
					return fmt.Errorf("unexpected value")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"pop bool",
			nil,
			func(s *stack) error {
				_, err := s.PopBool()
				return err
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"popInt 0",
			[][]byte{{0x0}},
			func(s *stack) error {
				v, err := s.PopInt()
				if err != nil {
					return err
				}
				if v != 0 {
					return fmt.Errorf("0 != 0 on popInt")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"popInt -0",
			[][]byte{{0x80}},
			func(s *stack) error {
				v, err := s.PopInt()
				if err != nil {
					return err
				}
				if v != 0 {
					return fmt.Errorf("-0 != 0 on popInt")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"popInt 1",
			[][]byte{{0x01}},
			func(s *stack) error {
				v, err := s.PopInt()
				if err != nil {
					return err
				}
				if v != 1 {
					return fmt.Errorf("1 != 1 on popInt")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"popInt 1 leading 0",
			[][]byte{{0x01, 0x00, 0x00, 0x00}},
			func(s *stack) error {
				v, err := s.PopInt()
				if err != nil {
					return err
				}
				if v != 1 {
					fmt.Printf("%v != %v\n", v, 1)
					return fmt.Errorf("1 != 1 on popInt")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"popInt -1",
			[][]byte{{0x81}},
			func(s *stack) error {
				v, err := s.PopInt()
				if err != nil {
					return err
				}
				if v != -1 {
					return fmt.Errorf("-1 != -1 on popInt")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"popInt -1 leading 0",
			[][]byte{{0x01, 0x00, 0x00, 0x80}},
			func(s *stack) error {
				v, err := s.PopInt()
				if err != nil {
					return err
				}
				if v != -1 {
					fmt.Printf("%v != %v\n", v, -1)
					return fmt.Errorf("-1 != -1 on popInt")
				}
				return nil
			},
			nil,
			nil,
		},
		// 触发 asInt 中的多字节情况
		{
			"popInt -513",
			[][]byte{{0x1, 0x82}},
			func(s *stack) error {
				v, err := s.PopInt()
				if err != nil {
					return err
				}
				if v != -513 {
					fmt.Printf("%v != %v\n", v, -513)
					return fmt.Errorf("1 != 1 on popInt")
				}
				return nil
			},
			nil,
			nil,
		},
		// 确认 asInt 代码不会修改基础数据。
		{
			"peekint nomodify -1",
			[][]byte{{0x01, 0x00, 0x00, 0x80}},
			func(s *stack) error {
				v, err := s.PeekInt(0)
				if err != nil {
					return err
				}
				if v != -1 {
					fmt.Printf("%v != %v\n", v, -1)
					return fmt.Errorf("-1 != -1 on popInt")
				}
				return nil
			},
			nil,
			[][]byte{{0x01, 0x00, 0x00, 0x80}},
		},
		{
			"PushInt 0",
			nil,
			func(s *stack) error {
				s.PushInt(scriptNum(0))
				return nil
			},
			nil,
			[][]byte{{}},
		},
		{
			"PushInt 1",
			nil,
			func(s *stack) error {
				s.PushInt(scriptNum(1))
				return nil
			},
			nil,
			[][]byte{{0x1}},
		},
		{
			"PushInt -1",
			nil,
			func(s *stack) error {
				s.PushInt(scriptNum(-1))
				return nil
			},
			nil,
			[][]byte{{0x81}},
		},
		{
			"PushInt two bytes",
			nil,
			func(s *stack) error {
				s.PushInt(scriptNum(256))
				return nil
			},
			nil,
			// little endian.. *sigh*
			[][]byte{{0x00, 0x01}},
		},
		{
			"PushInt leading zeros",
			nil,
			func(s *stack) error {
				// 这将设置高位
				s.PushInt(scriptNum(128))
				return nil
			},
			nil,
			[][]byte{{0x80, 0x00}},
		},
		{
			"dup",
			[][]byte{{1}},
			func(s *stack) error {
				return s.DupN(1)
			},
			nil,
			[][]byte{{1}, {1}},
		},
		{
			"dup2",
			[][]byte{{1}, {2}},
			func(s *stack) error {
				return s.DupN(2)
			},
			nil,
			[][]byte{{1}, {2}, {1}, {2}},
		},
		{
			"dup3",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.DupN(3)
			},
			nil,
			[][]byte{{1}, {2}, {3}, {1}, {2}, {3}},
		},
		{
			"dup0",
			[][]byte{{1}},
			func(s *stack) error {
				return s.DupN(0)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"dup-1",
			[][]byte{{1}},
			func(s *stack) error {
				return s.DupN(-1)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"dup too much",
			[][]byte{{1}},
			func(s *stack) error {
				return s.DupN(2)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"PushBool true",
			nil,
			func(s *stack) error {
				s.PushBool(true)

				return nil
			},
			nil,
			[][]byte{{1}},
		},
		{
			"PushBool false",
			nil,
			func(s *stack) error {
				s.PushBool(false)

				return nil
			},
			nil,
			[][]byte{nil},
		},
		{
			"PushBool PopBool",
			nil,
			func(s *stack) error {
				s.PushBool(true)
				val, err := s.PopBool()
				if err != nil {
					return err
				}
				if !val {
					return fmt.Errorf("unexpected value")
				}

				return nil
			},
			nil,
			nil,
		},
		{
			"PushBool PopBool 2",
			nil,
			func(s *stack) error {
				s.PushBool(false)
				val, err := s.PopBool()
				if err != nil {
					return err
				}
				if val {
					return fmt.Errorf("unexpected value")
				}

				return nil
			},
			nil,
			nil,
		},
		{
			"PushInt PopBool",
			nil,
			func(s *stack) error {
				s.PushInt(scriptNum(1))
				val, err := s.PopBool()
				if err != nil {
					return err
				}
				if !val {
					return fmt.Errorf("unexpected value")
				}

				return nil
			},
			nil,
			nil,
		},
		{
			"PushInt PopBool 2",
			nil,
			func(s *stack) error {
				s.PushInt(scriptNum(0))
				val, err := s.PopBool()
				if err != nil {
					return err
				}
				if val {
					return fmt.Errorf("unexpected value")
				}

				return nil
			},
			nil,
			nil,
		},
		{
			"Nip top",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.NipN(0)
			},
			nil,
			[][]byte{{1}, {2}},
		},
		{
			"Nip middle",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.NipN(1)
			},
			nil,
			[][]byte{{1}, {3}},
		},
		{
			"Nip low",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.NipN(2)
			},
			nil,
			[][]byte{{2}, {3}},
		},
		{
			"Nip too much",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				// bite off more than we can chew
				return s.NipN(3)
			},
			scriptError(ErrInvalidStackOperation, ""),
			[][]byte{{2}, {3}},
		},
		{
			"keep on tucking",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.Tuck()
			},
			nil,
			[][]byte{{1}, {3}, {2}, {3}},
		},
		{
			"a little tucked up",
			[][]byte{{1}}, // 塔克的论据太少
			func(s *stack) error {
				return s.Tuck()
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"all tucked up",
			nil, // 塔克的论据太少
			func(s *stack) error {
				return s.Tuck()
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"drop 1",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.DropN(1)
			},
			nil,
			[][]byte{{1}, {2}, {3}},
		},
		{
			"drop 2",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.DropN(2)
			},
			nil,
			[][]byte{{1}, {2}},
		},
		{
			"drop 3",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.DropN(3)
			},
			nil,
			[][]byte{{1}},
		},
		{
			"drop 4",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.DropN(4)
			},
			nil,
			nil,
		},
		{
			"drop 4/5",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.DropN(5)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"drop invalid",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.DropN(0)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Rot1",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.RotN(1)
			},
			nil,
			[][]byte{{1}, {3}, {4}, {2}},
		},
		{
			"Rot2",
			[][]byte{{1}, {2}, {3}, {4}, {5}, {6}},
			func(s *stack) error {
				return s.RotN(2)
			},
			nil,
			[][]byte{{3}, {4}, {5}, {6}, {1}, {2}},
		},
		{
			"Rot too little",
			[][]byte{{1}, {2}},
			func(s *stack) error {
				return s.RotN(1)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Rot0",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.RotN(0)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Swap1",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.SwapN(1)
			},
			nil,
			[][]byte{{1}, {2}, {4}, {3}},
		},
		{
			"Swap2",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.SwapN(2)
			},
			nil,
			[][]byte{{3}, {4}, {1}, {2}},
		},
		{
			"Swap too little",
			[][]byte{{1}},
			func(s *stack) error {
				return s.SwapN(1)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Swap0",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.SwapN(0)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Over1",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.OverN(1)
			},
			nil,
			[][]byte{{1}, {2}, {3}, {4}, {3}},
		},
		{
			"Over2",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.OverN(2)
			},
			nil,
			[][]byte{{1}, {2}, {3}, {4}, {1}, {2}},
		},
		{
			"Over too little",
			[][]byte{{1}},
			func(s *stack) error {
				return s.OverN(1)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Over0",
			[][]byte{{1}, {2}, {3}},
			func(s *stack) error {
				return s.OverN(0)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Pick1",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.PickN(1)
			},
			nil,
			[][]byte{{1}, {2}, {3}, {4}, {3}},
		},
		{
			"Pick2",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.PickN(2)
			},
			nil,
			[][]byte{{1}, {2}, {3}, {4}, {2}},
		},
		{
			"Pick too little",
			[][]byte{{1}},
			func(s *stack) error {
				return s.PickN(1)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Roll1",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.RollN(1)
			},
			nil,
			[][]byte{{1}, {2}, {4}, {3}},
		},
		{
			"Roll2",
			[][]byte{{1}, {2}, {3}, {4}},
			func(s *stack) error {
				return s.RollN(2)
			},
			nil,
			[][]byte{{1}, {3}, {4}, {2}},
		},
		{
			"Roll too little",
			[][]byte{{1}},
			func(s *stack) error {
				return s.RollN(1)
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
		{
			"Peek bool",
			[][]byte{{1}},
			func(s *stack) error {
				// Peek bool 在其他方面已经经过了很好的测试，只需检查它是否有效即可。
				val, err := s.PeekBool(0)
				if err != nil {
					return err
				}
				if !val {
					return fmt.Errorf("invalid result")
				}
				return nil
			},
			nil,
			[][]byte{{1}},
		},
		{
			"Peek bool 2",
			[][]byte{nil},
			func(s *stack) error {
				// Peek bool 在其他方面已经经过了很好的测试，只需检查它是否有效即可。
				val, err := s.PeekBool(0)
				if err != nil {
					return err
				}
				if val {
					return fmt.Errorf("invalid result")
				}
				return nil
			},
			nil,
			[][]byte{nil},
		},
		{
			"Peek int",
			[][]byte{{1}},
			func(s *stack) error {
				// Peek int 在其他方面已经经过了很好的测试，只需检查它是否有效即可。
				val, err := s.PeekInt(0)
				if err != nil {
					return err
				}
				if val != 1 {
					return fmt.Errorf("invalid result")
				}
				return nil
			},
			nil,
			[][]byte{{1}},
		},
		{
			"Peek int 2",
			[][]byte{{0}},
			func(s *stack) error {
				// Peek int 在其他方面经过了很好的测试，
				// 只是检查它是否有效。
				val, err := s.PeekInt(0)
				if err != nil {
					return err
				}
				if val != 0 {
					return fmt.Errorf("invalid result")
				}
				return nil
			},
			nil,
			[][]byte{{0}},
		},
		{
			"pop int",
			nil,
			func(s *stack) error {
				s.PushInt(scriptNum(1))
				// Peek int 在其他方面经过了很好的测试，
				// 只是检查它是否有效。
				val, err := s.PopInt()
				if err != nil {
					return err
				}
				if val != 1 {
					return fmt.Errorf("invalid result")
				}
				return nil
			},
			nil,
			nil,
		},
		{
			"pop empty",
			nil,
			func(s *stack) error {
				// Peek int 在其他方面经过了很好的测试，
				// 只是检查它是否有效。
				_, err := s.PopInt()
				return err
			},
			scriptError(ErrInvalidStackOperation, ""),
			nil,
		},
	}

	for _, test := range tests {
		// 设置初始堆栈状态并执行测试操作。
		s := stack{}
		for i := range test.before {
			s.PushByteArray(test.before[i])
		}
		err := test.operation(&s)

		// 确保错误代码是预期的类型，并且错误代码与测试实例中指定的值匹配。
		if e := tstCheckScriptError(err, test.err); e != nil {
			t.Errorf("%s: %v", test.name, e)
			continue
		}
		if err != nil {
			continue
		}

		// 确保生成的堆栈具有预期长度。
		if int32(len(test.after)) != s.Depth() {
			t.Errorf("%s: stack depth doesn't match expected: %v "+
				"vs %v", test.name, len(test.after),
				s.Depth())
			continue
		}

		// 确保生成的堆栈中的所有项目都是预期值。
		for i := range test.after {
			val, err := s.PeekByteArray(s.Depth() - int32(i) - 1)
			if err != nil {
				t.Errorf("%s: can't peek %dth stack entry: %v",
					test.name, i, err)
				break
			}

			if !bytes.Equal(val, test.after[i]) {
				t.Errorf("%s: %dth stack entry doesn't match "+
					"expected: %v vs %v", test.name, i, val,
					test.after[i])
				break
			}
		}
	}
}
