package bpfschain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"hash"
	"log"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/sirupsen/logrus"
	"github.com/tyler-smith/go-bip32"
	"golang.org/x/crypto/pbkdf2"
)

func TestDecodeAddress(t *testing.T) {
	// 将发送硬币的地址解析为btcutil.Address，这对于确保地址的准确性和确定地址类型很有用。
	// 即将到来的 PayToAddrScript 调用也需要它。
	addressStr := "12gpXQVcCL2qhTNQgyLVdCFG2Qs2px98nV"
	address, err := btcutil.DecodeAddress(addressStr, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Create a public key script that pays to the address.
	script, err := txscript.PayToAddrScript(address)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("十六进制脚本: %x\n", script)

	disasm, err := txscript.DisasmString(script)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("脚本反汇编:", disasm)

	// Output:
	// 十六进制脚本: 76a914128004ff2fcaf13b2b91eb654b1dc2b674f7ec6188ac
	// 脚本反汇编: OP_DUP OP_HASH160 128004ff2fcaf13b2b91eb654b1dc2b674f7ec61 OP_EQUALVERIFY OP_CHECKSIG
}

func TestTxscript(t *testing.T) {
	send := []byte("创世区块预留地址")
	w := NewWallet(send, nil)
	address := GetAddress(w.PublicKey)
	log.Printf("创世区块预留地址:\t%s", address)

	// 对地址的字符串编码进行解码，如果 addr 是已知地址类型的有效编码，则返回该地址。
	addr, err := btcutil.DecodeAddress(address, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}

	log.Printf("addr地址:\t%v", addr)
	log.Printf("addr地址:\t%v", addr.String())

	// 创建一个新脚本，用于向指定地址支付交易输出。
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		fmt.Println(err)
		return
	}

	log.Printf("script--:\t%x\n", pkScript)

	// 将反汇编脚本格式化为一行打印
	disasm, err := txscript.DisasmString(pkScript)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("脚本反汇编:\t%s\n", disasm)

	// 从脚本中提取公钥
	scriptClass, addrs, _, err := txscript.ExtractPkScriptAddrs(pkScript, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("addrs--:\t%v\n", addrs)
	fmt.Printf("scriptClass--:\t%v\n", scriptClass)
	fmt.Printf("PubKeyHashTy--:\t%v\n", txscript.PubKeyHashTy)
}

type Wallet struct {
	Mnemonic   []byte   // 助记词
	PrivateKey []byte   // 私钥
	PublicKey  []byte   // 公钥
	Password   [16]byte // 密码
}

// NewWallet 创建并返回一个钱包
func NewWallet(mnemonic, password []byte) *Wallet {
	privateKey, publicKey, err := GenerateECDSAKeyPair(mnemonic, password, 4096, elliptic.P256().Params().BitSize/8, false)
	if err != nil {
		logrus.Panic(err)
	}
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		logrus.Panic(err)
	}
	wallet := Wallet{
		Mnemonic:   mnemonic,  // 助记词
		PrivateKey: privBytes, // 私钥
		PublicKey:  publicKey, // 公钥
	}

	return &wallet
}

// generateECDSAKeyPair 从一个给定的种子（seed）生成椭圆曲线（Elliptic Curve）的密钥对.
// 接受种子（seed）、哈希函数类型（useSHA512）、盐（salt）、迭代次数（iterations）和密钥长度（keyLength）作为参数。
// 使用 PBKDF2 算法和指定的哈希函数从种子生成密钥。
// 然后，使用这个密钥和椭圆曲线算法生成 ECDSA 密钥对。
func GenerateECDSAKeyPair(password []byte, salt []byte, iterations, keyLength int, useSHA512 bool) (*ecdsa.PrivateKey, []byte, error) {
	curve := elliptic.P256() // 根据需要选择合适的曲线

	// 选择合适的哈希函数
	var hashFunc func() hash.Hash
	if useSHA512 {
		hashFunc = sha512.New
	} else {
		hashFunc = sha256.New
	}

	combined := append([]byte("BPFS"), salt...)

	// 使用 PBKDF2 生成强密钥
	key := pbkdf2.Key(password, combined, iterations, keyLength, hashFunc)

	// 生成主钱包
	masterKey, _ := bip32.NewMasterKey(key) //?????? 如果不使用启动host会报错

	// 生成私钥
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: new(big.Int).SetBytes(masterKey.Key),
	}

	// 计算公钥
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(masterKey.Key)

	// 生成公钥
	pubKey := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)

	return privateKey, pubKey, nil
}
