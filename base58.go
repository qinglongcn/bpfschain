package bpfschain

import (
	"bytes"
	"math/big"
)

// b58Alphabet 是Base58编码的字母表。
var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

// Base58Encode 函数接受一个字节切片输入，并返回其Base58编码的字节切片。
func Base58Encode(input []byte) []byte {
	// 初始化一个字节切片用于存储Base58编码结果。
	var result []byte

	// 将输入字节切片转换为大整数x。
	x := big.NewInt(0).SetBytes(input)

	// base是Base58字母表的长度，也是Base58的基数。
	base := big.NewInt(int64(len(b58Alphabet)))
	// zero是0的大整数表示，用于后面的比较。
	zero := big.NewInt(0)
	// mod用于存储除法运算的余数。
	mod := &big.Int{}

	// 当x不等于0时，继续进行除法运算并获取余数，将余数对应的Base58字母添加到结果切片中。
	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)                            // x除以base，商保存回x，余数保存到mod。
		result = append(result, b58Alphabet[mod.Int64()]) // 将余数对应的Base58字母添加到结果中。
	}

	// 如果输入的第一个字节是0x00，将Base58字母表的第一个字符添加到结果中。
	// 这是Base58Check编码中版本字节的一部分。
	if input[0] == 0x00 {
		result = append(result, b58Alphabet[0])
	}

	// 反转result字节切片，得到最终的Base58编码结果。
	ReverseBytes(result)

	// 返回Base58编码的字节切片。
	return result
}

// Base58Decode 解码Base58编码的数据
// Base58Decode 函数接受一个Base58编码的字节切片，并返回解码后的字节切片。
func Base58Decode(input []byte) []byte {
	// 初始化一个大整数，用于存储解码的结果
	result := big.NewInt(0)

	// 遍历输入的每一个字节
	for _, b := range input {
		// 查找当前字节在Base58字母表中的索引
		charIndex := bytes.IndexByte(b58Alphabet, b)

		// 将当前的结果乘以58（Base58的基数）
		result.Mul(result, big.NewInt(58))

		// 加上当前字节在Base58字母表中的索引
		result.Add(result, big.NewInt(int64(charIndex)))
	}

	// 将大整数转换为字节切片
	decoded := result.Bytes()

	// 如果输入的第一个字节是Base58字母表的第一个字符，
	// 则在解码结果的前面添加一个0x00字节
	if input[0] == b58Alphabet[0] {
		decoded = append([]byte{0x00}, decoded...)
	}

	// 返回解码后的字节切片
	return decoded
}
