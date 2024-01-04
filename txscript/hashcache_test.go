// 包含测试哈希缓存功能的代码。

package txscript

import (
	"math/rand"
	"testing"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
)

func init() {
	rand.Seed(time.Now().Unix())
}

// genTestTx 创建一个随机事务以在测试用例中使用。
func genTestTx() (*wire.MsgTx, *MultiPrevOutFetcher, error) {
	tx := wire.NewMsgTx(2)
	tx.Version = rand.Int31()

	prevOuts := NewMultiPrevOutFetcher(nil)

	numTxins := 1 + rand.Intn(11)
	for i := 0; i < numTxins; i++ {
		randTxIn := wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Index: uint32(rand.Int31()),
			},
			Sequence: uint32(rand.Int31()),
		}
		_, err := rand.Read(randTxIn.PreviousOutPoint.Hash[:])
		if err != nil {
			return nil, nil, err
		}

		tx.TxIn = append(tx.TxIn, &randTxIn)

		prevOuts.AddPrevOut(
			randTxIn.PreviousOutPoint, &wire.TxOut{},
		)
	}

	numTxouts := 1 + rand.Intn(11)
	for i := 0; i < numTxouts; i++ {
		randTxOut := wire.TxOut{
			Value:    rand.Int63(),
			PkScript: make([]byte, rand.Intn(30)),
		}
		if _, err := rand.Read(randTxOut.PkScript); err != nil {
			return nil, nil, err
		}
		tx.TxOut = append(tx.TxOut, &randTxOut)
	}

	return tx, prevOuts, nil
}

// TestHashCacheAddContainsHashes 测试将项目添加到哈希缓存后，ContainsHashes 方法对所有插入的项目返回 true。
// 相反，ContainsHashes 应该对散列缓存中 _not_ 中的任何项返回 false。
func TestHashCacheAddContainsHashes(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(10)

	var (
		err          error
		randPrevOuts *MultiPrevOutFetcher
	)
	prevOuts := NewMultiPrevOutFetcher(nil)

	// 首先，我们将生成 10 个随机交易以供我们的测试使用。
	const numTxns = 10
	txns := make([]*wire.MsgTx, numTxns)
	for i := 0; i < numTxns; i++ {
		txns[i], randPrevOuts, err = genTestTx()
		if err != nil {
			t.Fatalf("unable to generate test tx: %v", err)
		}

		prevOuts.Merge(randPrevOuts)
	}

	// 生成交易后，我们将把它们添加到哈希缓存中。
	for _, tx := range txns {
		cache.AddSigHashes(tx, prevOuts)
	}

	// 接下来，我们将确保 ContainsHashes 方法正确定位插入到缓存中的每个事务。
	for _, tx := range txns {
		txid := tx.TxHash()
		if ok := cache.ContainsHashes(&txid); !ok {
			t.Fatalf("txid %v not found in cache but should be: ",
				txid)
		}
	}

	randTx, _, err := genTestTx()
	if err != nil {
		t.Fatalf("unable to generate tx: %v", err)
	}

	// 最后，我们将断言 ContainsHashes 方法不会将未添加到缓存的事务报告为存在。
	randTxid := randTx.TxHash()
	if ok := cache.ContainsHashes(&randTxid); ok {
		t.Fatalf("txid %v wasn't inserted into cache but was found",
			randTxid)
	}
}

// TestHashCacheAddGet 测试 GetSigHashes 函数是否正确检索特定交易的叹息。
func TestHashCacheAddGet(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(10)

	// 首先，我们将生成一个随机交易并计算该交易的叹息集。
	randTx, prevOuts, err := genTestTx()
	if err != nil {
		t.Fatalf("unable to generate tx: %v", err)
	}
	sigHashes := NewTxSigHashes(randTx, prevOuts)

	// 接下来，将事务添加到哈希缓存中。
	cache.AddSigHashes(randTx, prevOuts)

	// 上面插入缓存的事务应该可以找到。
	txid := randTx.TxHash()
	cacheHashes, ok := cache.GetSigHashes(&txid)
	if !ok {
		t.Fatalf("tx %v wasn't found in cache", txid)
	}

	// 最后，检索到的叹息应该与最初插入缓存的叹息完全匹配。
	if *sigHashes != *cacheHashes {
		t.Fatalf("sighashes don't match: expected %v, got %v",
			spew.Sdump(sigHashes), spew.Sdump(cacheHashes))
	}
}

// TestHashCachePurge 测试是否能够从哈希缓存中正确删除项目。
func TestHashCachePurge(t *testing.T) {
	t.Parallel()

	cache := NewHashCache(10)

	var (
		err          error
		randPrevOuts *MultiPrevOutFetcher
	)
	prevOuts := NewMultiPrevOutFetcher(nil)

	// 首先，我们首先将 numTxns 事务插入哈希缓存。
	const numTxns = 10
	txns := make([]*wire.MsgTx, numTxns)
	for i := 0; i < numTxns; i++ {
		txns[i], randPrevOuts, err = genTestTx()
		if err != nil {
			t.Fatalf("unable to generate test tx: %v", err)
		}

		prevOuts.Merge(randPrevOuts)
	}
	for _, tx := range txns {
		cache.AddSigHashes(tx, prevOuts)
	}

	// 插入所有事务后，我们将从哈希缓存中清除它们。
	for _, tx := range txns {
		txid := tx.TxHash()
		cache.PurgeSigHashes(&txid)
	}

	// 此时，在缓存中应该找不到插入哈希缓存的任何事务。
	for _, tx := range txns {
		txid := tx.TxHash()
		if ok := cache.ContainsHashes(&txid); ok {
			t.Fatalf("tx %v found in cache but should have "+
				"been purged: ", txid)
		}
	}
}
