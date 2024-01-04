package bpfschain

import (
	"fmt"
	"testing"
)

// EncodeToBytes 函数接受任意数据类型并返回其 gob 编码的 []byte 表示。
// DecodeFromBytes 函数接受一个 gob 编码的 []byte 和一个指向要解码到的数据结构的指针，然后将数据解码到该结构中。
func TestCodeAndByte(t *testing.T) {
	// 示例使用
	type Person struct {
		Name string
		Age  int
	}

	p := Person{Name: "Alice", Age: 30}

	encodedData, err := EncodeToBytes(p)
	if err != nil {
		fmt.Println("Encoding failed:", err)
		return
	}

	var decodedPerson Person
	err = DecodeFromBytes(encodedData, &decodedPerson)
	if err != nil {
		fmt.Println("Decoding failed:", err)
		return
	}

	fmt.Println("Decoded data:", decodedPerson)
}
