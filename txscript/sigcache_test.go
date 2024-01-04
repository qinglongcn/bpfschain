// 包含测试签名缓存功能的代码。

package txscript

import (
	"crypto/rand"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// genRandomSig 返回一条随机消息，该消息在公钥和公钥下的签名。 该函数用于生成随机测试数据。
func genRandomSig() (*chainhash.Hash, *ecdsa.Signature, *btcec.PublicKey, error) {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, nil, err
	}

	var msgHash chainhash.Hash
	if _, err := rand.Read(msgHash[:]); err != nil {
		return nil, nil, nil, err
	}

	sig := ecdsa.Sign(privKey, msgHash[:])

	return &msgHash, sig, privKey.PubKey(), nil
}

// TestSigCacheAddExists 测试添加签名三元组并随后检查签名缓存中是否存在的能力。
func TestSigCacheAddExists(t *testing.T) {
	sigCache := NewSigCache(200)

	// 生成随机 sigCache 条目三元组。
	msg1, sig1, key1, err := genRandomSig()
	if err != nil {
		t.Errorf("unable to generate random signature test data")
	}

	// 将三元组添加到签名缓存中。
	sigCache.Add(*msg1, sig1.Serialize(), key1.SerializeCompressed())

	// 现在应该可以在 sigcache 中找到之前添加的三元组。
	sig1Copy, _ := ecdsa.ParseSignature(sig1.Serialize())
	key1Copy, _ := btcec.ParsePubKey(key1.SerializeCompressed())
	if !sigCache.Exists(*msg1, sig1Copy.Serialize(), key1Copy.SerializeCompressed()) {
		t.Errorf("previously added item not found in signature cache")
	}
}

// TestSigCacheAddEvictEntry 测试驱逐情况，其中将新的签名三元组添加到完整签名缓存中，这应该触发随机驱逐，然后将新元素添加到缓存中。
func TestSigCacheAddEvictEntry(t *testing.T) {
	// 创建一个最多可容纳 100 个条目的 sigcache。
	sigCacheSize := uint(100)
	sigCache := NewSigCache(sigCacheSize)

	// 用一些随机的 sig 三元组填充 sigcache。
	for i := uint(0); i < sigCacheSize; i++ {
		msg, sig, key, err := genRandomSig()
		if err != nil {
			t.Fatalf("unable to generate random signature test data")
		}

		sigCache.Add(*msg, sig.Serialize(), key.SerializeCompressed())

		sigCopy, err := ecdsa.ParseSignature(sig.Serialize())
		if err != nil {
			t.Fatalf("unable to parse sig: %v", err)
		}
		keyCopy, err := btcec.ParsePubKey(key.SerializeCompressed())
		if err != nil {
			t.Fatalf("unable to parse key: %v", err)
		}
		if !sigCache.Exists(*msg, sigCopy.Serialize(), keyCopy.SerializeCompressed()) {
			t.Errorf("previously added item not found in signature" +
				"cache")
		}
	}

	// sigcache 现在应该有 sigCacheSize 条目。
	if uint(len(sigCache.validSigs)) != sigCacheSize {
		t.Fatalf("sigcache should now have %v entries, instead it has %v",
			sigCacheSize, len(sigCache.validSigs))
	}

	// 添加新条目，这应该会导致随机选择的先前条目被驱逐。
	msgNew, sigNew, keyNew, err := genRandomSig()
	if err != nil {
		t.Fatalf("unable to generate random signature test data")
	}
	sigCache.Add(*msgNew, sigNew.Serialize(), keyNew.SerializeCompressed())

	// sigcache 应该仍然有 sigCache 条目。
	if uint(len(sigCache.validSigs)) != sigCacheSize {
		t.Fatalf("sigcache should now have %v entries, instead it has %v",
			sigCacheSize, len(sigCache.validSigs))
	}

	// 上面添加的条目应该可以在 sigcache 中找到。
	sigNewCopy, _ := ecdsa.ParseSignature(sigNew.Serialize())
	keyNewCopy, _ := btcec.ParsePubKey(keyNew.SerializeCompressed())
	if !sigCache.Exists(*msgNew, sigNewCopy.Serialize(), keyNewCopy.SerializeCompressed()) {
		t.Fatalf("previously added item not found in signature cache")
	}
}

// TestSigCacheAddMaxEntriesZeroOrNegative 测试如果创建的 sigCache 的最大大小 <= 0，则根本不会向 sigcache 添加任何条目。
func TestSigCacheAddMaxEntriesZeroOrNegative(t *testing.T) {
	// 创建最多可容纳 0 个条目的 sigcache。
	sigCache := NewSigCache(0)

	// 生成随机 sigCache 条目三元组。
	msg1, sig1, key1, err := genRandomSig()
	if err != nil {
		t.Errorf("unable to generate random signature test data")
	}

	// 将三元组添加到签名缓存中。
	sigCache.Add(*msg1, sig1.Serialize(), key1.SerializeCompressed())

	// 不应找到生成的三元组。
	sig1Copy, _ := ecdsa.ParseSignature(sig1.Serialize())
	key1Copy, _ := btcec.ParsePubKey(key1.SerializeCompressed())
	if sigCache.Exists(*msg1, sig1Copy.Serialize(), key1Copy.SerializeCompressed()) {
		t.Errorf("previously added signature found in sigcache, but" +
			"shouldn't have been")
	}

	// sigCache 中不应有任何条目。
	if len(sigCache.validSigs) != 0 {
		t.Errorf("%v items found in sigcache, no items should have"+
			"been added", len(sigCache.validSigs))
	}
}
