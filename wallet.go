package bpfschain

import (
	"bytes"
	"crypto/sha256"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const addressChecksumLen = 4

// HashPubKey 函数接受一个公钥的字节切片，返回该公钥的RIPEMD160哈希。
func HashPubKey(pubKey []byte) []byte {
	// 使用SHA256算法对公钥进行哈希
	publicSHA256 := sha256.Sum256(pubKey)

	// 创建一个RIPEMD160的哈希器
	RIPEMD160Hasher := ripemd160.New()

	// 将SHA256哈希的结果写入RIPEMD160哈希器
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	// 如果有写入错误，则抛出panic
	if err != nil {
		logrus.Panic(err)
	}

	// 计算RIPEMD160哈希的结果
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	// 返回RIPEMD160哈希的结果
	return publicRIPEMD160
}

// GetAddress 返回公钥钱包地址
func GetAddress(pubKey []byte) string {
	pubKeyHash := HashPubKey(pubKey)

	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)

	return string(address)
}

// Checksum 为公钥生成校验和
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

// ValidateAddress 检查地址是否有效
func ValidateAddress(address string) bool {

	if len(address) != 34 {
		return false
	}
	pubKeyHash := Base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Equal(actualChecksum, targetChecksum)
}
