// 包含测试 Taproot 相关脚本处理的代码。

package txscript

import (
	"bytes"
	"encoding/hex"
	"fmt"
	prand "math/rand"
	"testing"
	"testing/quick"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

var (
	testPubBytes, _ = hex.DecodeString("F9308A019258C31049344F85F89D5229B" +
		"531C845836F99B08601F113BCE036F9")

	// rootKey 是测试向量中定义的测试根密钥:
	// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki
	rootKey, _ = hdkeychain.NewKeyFromString(
		"xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLi" +
			"sriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu",
	)

	//  accountPath是BIP86的基本路径(m/86'/0'/0').
	accountPath = []uint32{
		86 + hdkeychain.HardenedKeyStart, hdkeychain.HardenedKeyStart,
		hdkeychain.HardenedKeyStart,
	}
	expectedExternalAddresses = []string{
		"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
		"bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh",
	}
	expectedInternalAddresses = []string{
		"bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
	}
)

// TestControlBlockParsing 测试我们是否能够生成和解析有效的控制块。
func TestControlBlockParsing(t *testing.T) {
	t.Parallel()

	var testCases = []struct {
		controlBlockGen func() []byte
		valid           bool
	}{
		// 无效的控制块，它只有 5 个字节，并且至少需要 33 个字节。
		{
			controlBlockGen: func() []byte {
				return bytes.Repeat([]byte{0x00}, 5)
			},
			valid: false,
		},

		// 无效控制块，它大于可接受的最大控制块。
		{
			controlBlockGen: func() []byte {
				return bytes.Repeat([]byte{0x00}, ControlBlockMaxSize+1)
			},
			valid: false,
		},

		// 无效的控制块，尽管它具有有效的起始字节长度，但它不是 32 字节的倍数。
		{
			controlBlockGen: func() []byte {
				return bytes.Repeat([]byte{0x00}, ControlBlockBaseSize+34)
			},
			valid: false,
		},

		// 有效的控制块，具有最大可能的大小。
		{
			controlBlockGen: func() []byte {
				privKey, _ := btcec.NewPrivateKey()
				pubKey := privKey.PubKey()

				yIsOdd := (pubKey.SerializeCompressed()[0] ==
					secp.PubKeyFormatCompressedOdd)

				ctrl := ControlBlock{
					InternalKey:     pubKey,
					OutputKeyYIsOdd: yIsOdd,
					LeafVersion:     BaseLeafVersion,
					InclusionProof: bytes.Repeat(
						[]byte{0x00},
						ControlBlockMaxSize-ControlBlockBaseSize,
					),
				}

				ctrlBytes, _ := ctrl.ToBytes()
				return ctrlBytes
			},
			valid: true,
		},

		// 有效的控制块在证明中仅具有单个元素，因为树仅具有单个元素。
		{
			controlBlockGen: func() []byte {
				privKey, _ := btcec.NewPrivateKey()
				pubKey := privKey.PubKey()

				yIsOdd := (pubKey.SerializeCompressed()[0] ==
					secp.PubKeyFormatCompressedOdd)

				ctrl := ControlBlock{
					InternalKey:     pubKey,
					OutputKeyYIsOdd: yIsOdd,
					LeafVersion:     BaseLeafVersion,
					InclusionProof: bytes.Repeat(
						[]byte{0x00}, ControlBlockNodeSize,
					),
				}

				ctrlBytes, _ := ctrl.ToBytes()
				return ctrlBytes
			},
			valid: true,
		},
	}
	for i, testCase := range testCases {
		ctrlBlockBytes := testCase.controlBlockGen()

		ctrlBlock, err := ParseControlBlock(ctrlBlockBytes)
		switch {
		case testCase.valid && err != nil:
			t.Fatalf("#%v: unable to parse valid control block: %v", i, err)

		case !testCase.valid && err == nil:
			t.Fatalf("#%v: invalid control block should have failed: %v", i, err)
		}

		if !testCase.valid {
			continue
		}

		// 如果我们序列化控制块，我们应该获得与输入完全相同的字节集。
		ctrlBytes, err := ctrlBlock.ToBytes()
		if err != nil {
			t.Fatalf("#%v: unable to encode bytes: %v", i, err)
		}
		if !bytes.Equal(ctrlBytes, ctrlBlockBytes) {
			t.Fatalf("#%v: encoding mismatch: expected %x, "+
				"got %x", i, ctrlBlockBytes, ctrlBytes)
		}
	}
}

// TestTaprootScriptSpendTweak 测试对于任何 32 字节的假设脚本根，调整后的公钥与调整私钥然后从中生成公钥相同。
// 此测试是一个快速检查测试，以断言以下不变量:
//
//   - taproot_tweak_pubkey(pubkey_gen(seckey), h)[1] ==
//     pubkey_gen(taproot_tweak_seckey(seckey, h))
func TestTaprootScriptSpendTweak(t *testing.T) {
	t.Parallel()

	// 断言如果我们使用这个 x 值作为脚本根的哈希值，那么如果我们生成一个调整后的公钥，它与我们使用该密钥生成调整后的私钥，然后从中生成公钥相同的密钥 。
	f := func(x [32]byte) bool {
		privKey, err := btcec.NewPrivateKey()
		if err != nil {
			return false
		}

		// 使用 x 值作为脚本根生成调整后的公钥。
		tweakedPub := ComputeTaprootOutputKey(privKey.PubKey(), x[:])

		// 现在我们将生成相应的调整后的私钥。
		tweakedPriv := TweakTaprootPrivKey(*privKey, x[:])

		// 该私钥的公钥应该与我们上面生成的调整后的公钥相同。
		return tweakedPub.IsEqual(tweakedPriv.PubKey()) &&
			bytes.Equal(
				schnorr.SerializePubKey(tweakedPub),
				schnorr.SerializePubKey(tweakedPriv.PubKey()),
			)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Fatalf("tweaked public/private key mapping is "+
			"incorrect: %v", err)
	}

}

// TestTaprootTweakNoMutation 测试传递到 TweakTaprootPrivKey 的底层私钥永远不会发生变化。
func TestTaprootTweakNoMutation(t *testing.T) {
	t.Parallel()

	// 断言给定随机调整和随机私钥，如果我们调整私钥，它不会受到影响。
	f := func(privBytes, tweak [32]byte) bool {
		privKey, _ := btcec.PrivKeyFromBytes(privBytes[:])

		// 现在我们将生成相应的调整后的私钥。
		tweakedPriv := TweakTaprootPrivKey(*privKey, tweak[:])

		// 调整后的私钥和原始私钥不应相同。
		if *privKey == *tweakedPriv {
			t.Logf("private key was mutated")
			return false
		}

		// 我们应该能够从原始字节重新派生私钥并再次匹配。
		privKeyCopy, _ := btcec.PrivKeyFromBytes(privBytes[:])
		if *privKey != *privKeyCopy {
			t.Logf("private doesn't match")
			return false
		}

		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Fatalf("private key modified: %v", err)
	}
}

// TestTaprootConstructKeyPath 测试的关键只花主根建设。
func TestTaprootConstructKeyPath(t *testing.T) {
	checkPath := func(branch uint32, expectedAddresses []string) {
		path, err := derivePath(rootKey, append(accountPath, branch))
		require.NoError(t, err)

		for index, expectedAddr := range expectedAddresses {
			extendedKey, err := path.Derive(uint32(index))
			require.NoError(t, err)

			pubKey, err := extendedKey.ECPubKey()
			require.NoError(t, err)

			tapKey := ComputeTaprootKeyNoScript(pubKey)

			addr, err := btcutil.NewAddressTaproot(
				schnorr.SerializePubKey(tapKey),
				&chaincfg.MainNetParams,
			)
			require.NoError(t, err)

			require.Equal(t, expectedAddr, addr.String())
		}
	}
	checkPath(0, expectedExternalAddresses)
	checkPath(1, expectedInternalAddresses)
}

func derivePath(key *hdkeychain.ExtendedKey, path []uint32) (
	*hdkeychain.ExtendedKey, error) {

	var (
		currentKey = key
		err        error
	)
	for _, pathPart := range path {
		currentKey, err = currentKey.Derive(pathPart)
		if err != nil {
			return nil, err
		}
	}
	return currentKey, nil
}

// TestTapscriptCommitmentVerification 给定一个有效的控制块，证明我们能够生成和验证验证脚本树叶包含证明。
func TestTapscriptCommitmentVerification(t *testing.T) {
	t.Parallel()

	// 从 0 片叶子到 1 片叶子确保正确验证
	testCases := []struct {
		numLeaves int

		valid bool

		treeMutateFunc func(*IndexedTapScriptTree)

		ctrlBlockMutateFunc func(*ControlBlock)
	}{
		// 单叶的有效默克尔证明。
		{
			numLeaves: 1,
			valid:     true,
		},

		// 具有奇数叶子的有效默克尔证明序列。
		{
			numLeaves: 3,
			valid:     true,
		},

		// 具有偶数叶子的有效系列默克尔证明。
		{
			numLeaves: 4,
			valid:     true,
		},

		// 对于无效的默克尔证明，我们修改其中一个叶子的最后一个字节。
		{
			numLeaves: 4,
			valid:     false,
			treeMutateFunc: func(t *IndexedTapScriptTree) {
				for _, leafProof := range t.LeafMerkleProofs {
					leafProof.InclusionProof[0] ^= 1
				}
			},
		},

		{
			// 一系列无效的证明，我们修改控制块以使其与最终输出密钥承诺的奇偶校验不匹配。
			numLeaves: 2,
			valid:     false,
			ctrlBlockMutateFunc: func(c *ControlBlock) {
				c.OutputKeyYIsOdd = !c.OutputKeyYIsOdd
			},
		},
	}
	for _, testCase := range testCases {
		testName := fmt.Sprintf("num_leaves=%v, valid=%v, treeMutate=%v, "+
			"ctrlBlockMutate=%v", testCase.numLeaves, testCase.valid,
			testCase.treeMutateFunc == nil, testCase.ctrlBlockMutateFunc == nil)

		t.Run(testName, func(t *testing.T) {
			tapScriptLeaves := make([]TapLeaf, testCase.numLeaves)
			for i := 0; i < len(tapScriptLeaves); i++ {
				numLeafBytes := prand.Intn(1000)
				scriptBytes := make([]byte, numLeafBytes)
				if _, err := prand.Read(scriptBytes[:]); err != nil {
					t.Fatalf("unable to read rand bytes: %v", err)
				}
				tapScriptLeaves[i] = NewBaseTapLeaf(scriptBytes)
			}

			scriptTree := AssembleTaprootScriptTree(tapScriptLeaves...)

			if testCase.treeMutateFunc != nil {
				testCase.treeMutateFunc(scriptTree)
			}

			internalKey, _ := btcec.NewPrivateKey()

			rootHash := scriptTree.RootNode.TapHash()
			outputKey := ComputeTaprootOutputKey(
				internalKey.PubKey(), rootHash[:],
			)

			for _, leafProof := range scriptTree.LeafMerkleProofs {
				ctrlBlock := leafProof.ToControlBlock(
					internalKey.PubKey(),
				)

				if testCase.ctrlBlockMutateFunc != nil {
					testCase.ctrlBlockMutateFunc(&ctrlBlock)
				}

				err := VerifyTaprootLeafCommitment(
					&ctrlBlock, schnorr.SerializePubKey(outputKey),
					leafProof.TapLeaf.Script,
				)
				valid := err == nil

				if valid != testCase.valid {
					t.Fatalf("test case mismatch: expected "+
						"valid=%v, got valid=%v", testCase.valid,
						valid)
				}
			}

			// TODO(roasbeef): 索引正确性
		})
	}
}
