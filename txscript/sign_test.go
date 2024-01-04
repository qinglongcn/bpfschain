// 含测试交易签名功能的代码。

package txscript

import (
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/stretchr/testify/require"
)

type addressToKey struct {
	key        *btcec.PrivateKey
	compressed bool
}

func mkGetKey(keys map[string]addressToKey) KeyDB {
	if keys == nil {
		return KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey,
			bool, error) {
			return nil, false, fmt.Errorf("nope")
		})
	}
	return KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey,
		bool, error) {
		a2k, ok := keys[addr.EncodeAddress()]
		if !ok {
			return nil, false, fmt.Errorf("nope")
		}
		return a2k.key, a2k.compressed, nil
	})
}

func mkGetScript(scripts map[string][]byte) ScriptDB {
	if scripts == nil {
		return ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
			return nil, fmt.Errorf("nope")
		})
	}
	return ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
		script, ok := scripts[addr.EncodeAddress()]
		if !ok {
			return nil, fmt.Errorf("nope")
		}
		return script, nil
	})
}

func checkScripts(msg string, tx *wire.MsgTx, idx int, inputAmt int64, sigScript, pkScript []byte) error {
	tx.TxIn[idx].SignatureScript = sigScript
	vm, err := NewEngine(pkScript, tx, idx, ScriptBip16|ScriptVerifyDERSignatures, nil, nil, inputAmt, nil)
	if err != nil {
		return fmt.Errorf("failed to make script engine for %s: %v",
			msg, err)
	}

	err = vm.Execute()
	if err != nil {
		return fmt.Errorf("invalid script signature for %s: %v", msg,
			err)
	}

	return nil
}

func signAndCheck(msg string, tx *wire.MsgTx, idx int, inputAmt int64, pkScript []byte,
	hashType SigHashType, kdb KeyDB, sdb ScriptDB,
	previousScript []byte) error {

	sigScript, err := SignTxOutput(&chaincfg.TestNet3Params, tx, idx,
		pkScript, hashType, kdb, sdb, nil)
	if err != nil {
		return fmt.Errorf("failed to sign output %s: %v", msg, err)
	}

	return checkScripts(msg, tx, idx, inputAmt, sigScript, pkScript)
}

func TestSignTxOutput(t *testing.T) {
	t.Parallel()

	// 制作钥匙
	// 根据 key 制作脚本。
	// 用魔法精灵尘埃签名。
	hashTypes := []SigHashType{
		SigHashOld, // 不再使用，但应该像所有一样
		SigHashAll,
		SigHashNone,
		SigHashSingle,
		SigHashAll | SigHashAnyOneCanPay,
		SigHashNone | SigHashAnyOneCanPay,
		SigHashSingle | SigHashAnyOneCanPay,
	}
	inputAmounts := []int64{5, 10, 15}
	tx := &wire.MsgTx{
		Version: 1,
		TxIn: []*wire.TxIn{
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 0,
				},
				Sequence: 4294967295,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 1,
				},
				Sequence: 4294967295,
			},
			{
				PreviousOutPoint: wire.OutPoint{
					Hash:  chainhash.Hash{},
					Index: 2,
				},
				Sequence: 4294967295,
			},
		},
		TxOut: []*wire.TxOut{
			{
				Value: 1,
			},
			{
				Value: 2,
			},
			{
				Value: 3,
			},
		},
		LockTime: 0,
	}

	// 支付到 Pubkey 哈希（未压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)
			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			if err := signAndCheck(
				msg,
				tx,
				i,
				inputAmounts[i],
				pkScript,
				hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}),
				mkGetScript(nil),
				nil,
			); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 支付到 Pubkey 哈希（未压缩）（与正确的合并）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)
			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(nil), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(nil), sigScript)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i], sigScript, pkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 支付到 Pubkey 哈希（压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(nil), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 通过重复合并支付到 Pubkey 哈希（压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(nil), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(nil), sigScript)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i],
				sigScript, pkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 支付到 PubKey（未压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(nil), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 支付到 PubKey（未压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(nil), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(nil), sigScript)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i], sigScript, pkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 支付到公钥（压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(nil), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 支付到公钥（压缩） with duplicate merge
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(nil), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, pkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(nil), sigScript)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i],
				sigScript, pkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 和以前一样，但现在使用 p2sh。
	// 支付给 Pubkey 哈希（未压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)
			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
				break
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(
				scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 通过重复合并支付给 Pubkey Hash（未压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)
			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
				break
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(
				scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i],
				sigScript, scriptPkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 支付到 Pubkey 哈希（压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(
				scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 支付到 Pubkey 哈希（压缩） 具有重复合并
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKeyHash(
				btcutil.Hash160(pk), &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(
				scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i],
				sigScript, scriptPkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 支付到 PubKey（未压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(
				scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 支付到 PubKey（未压缩） 具有重复合并
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeUncompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, false},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i],
				sigScript, scriptPkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 支付到公钥（压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 支付到公钥（压缩）
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk := key.PubKey().SerializeCompressed()
			address, err := btcutil.NewAddressPubKey(pk,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			pkScript, err := PayToAddrScript(address)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 通过上面的循环，这应该是有效的，现在再次签名并合并。
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address.EncodeAddress(): {key, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s a "+
					"second time: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i],
				sigScript, scriptPkScript)
			if err != nil {
				t.Errorf("twice signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 基本多重签名
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key1, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk1 := key1.PubKey().SerializeCompressed()
			address1, err := btcutil.NewAddressPubKey(pk1,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			key2, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey 2 for %s: %v",
					msg, err)
				break
			}

			pk2 := key2.PubKey().SerializeCompressed()
			address2, err := btcutil.NewAddressPubKey(pk2,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address 2 for %s: %v",
					msg, err)
				break
			}

			pkScript, err := MultiSigScript(
				[]*btcutil.AddressPubKey{address1, address2},
				2)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			if err := signAndCheck(msg, tx, i, inputAmounts[i],
				scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.EncodeAddress(): {key1, true},
					address2.EncodeAddress(): {key2, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil); err != nil {
				t.Error(err)
				break
			}
		}
	}

	// 两部分多重签名，先用一把钥匙签名，然后用另一把钥匙签名。
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key1, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk1 := key1.PubKey().SerializeCompressed()
			address1, err := btcutil.NewAddressPubKey(pk1,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			key2, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey 2 for %s: %v",
					msg, err)
				break
			}

			pk2 := key2.PubKey().SerializeCompressed()
			address2, err := btcutil.NewAddressPubKey(pk2,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address 2 for %s: %v",
					msg, err)
				break
			}

			pkScript, err := MultiSigScript(
				[]*btcutil.AddressPubKey{address1, address2},
				2)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.EncodeAddress(): {key1, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 只有二分之一签名，这“应该”失败。
			if checkScripts(msg, tx, i, inputAmounts[i], sigScript,
				scriptPkScript) == nil {
				t.Errorf("part signed script valid for %s", msg)
				break
			}

			// 用另一把钥匙签名并合并
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address2.EncodeAddress(): {key2, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), sigScript)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg, err)
				break
			}

			err = checkScripts(msg, tx, i, inputAmounts[i], sigScript,
				scriptPkScript)
			if err != nil {
				t.Errorf("fully signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}

	// 两部分多重签名，用一把密钥签名，然后用两把密钥签名，正确检查密钥重复数据删除。
	for _, hashType := range hashTypes {
		for i := range tx.TxIn {
			msg := fmt.Sprintf("%d:%d", hashType, i)

			key1, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey for %s: %v",
					msg, err)
				break
			}

			pk1 := key1.PubKey().SerializeCompressed()
			address1, err := btcutil.NewAddressPubKey(pk1,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address for %s: %v",
					msg, err)
				break
			}

			key2, err := btcec.NewPrivateKey()
			if err != nil {
				t.Errorf("failed to make privKey 2 for %s: %v",
					msg, err)
				break
			}

			pk2 := key2.PubKey().SerializeCompressed()
			address2, err := btcutil.NewAddressPubKey(pk2,
				&chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make address 2 for %s: %v",
					msg, err)
				break
			}

			pkScript, err := MultiSigScript(
				[]*btcutil.AddressPubKey{address1, address2},
				2)
			if err != nil {
				t.Errorf("failed to make pkscript "+
					"for %s: %v", msg, err)
			}

			scriptAddr, err := btcutil.NewAddressScriptHash(
				pkScript, &chaincfg.TestNet3Params)
			if err != nil {
				t.Errorf("failed to make p2sh addr for %s: %v",
					msg, err)
				break
			}

			scriptPkScript, err := PayToAddrScript(scriptAddr)
			if err != nil {
				t.Errorf("failed to make script pkscript for "+
					"%s: %v", msg, err)
				break
			}

			sigScript, err := SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.EncodeAddress(): {key1, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), nil)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg,
					err)
				break
			}

			// 只有二分之一签名，这“应该”失败。
			if checkScripts(msg, tx, i, inputAmounts[i], sigScript,
				scriptPkScript) == nil {
				t.Errorf("part signed script valid for %s", msg)
				break
			}

			// 用另一把钥匙签名并合并
			sigScript, err = SignTxOutput(&chaincfg.TestNet3Params,
				tx, i, scriptPkScript, hashType,
				mkGetKey(map[string]addressToKey{
					address1.EncodeAddress(): {key1, true},
					address2.EncodeAddress(): {key2, true},
				}), mkGetScript(map[string][]byte{
					scriptAddr.EncodeAddress(): pkScript,
				}), sigScript)
			if err != nil {
				t.Errorf("failed to sign output %s: %v", msg, err)
				break
			}

			// 现在我们应该过去了。
			err = checkScripts(msg, tx, i, inputAmounts[i],
				sigScript, scriptPkScript)
			if err != nil {
				t.Errorf("fully signed script invalid for "+
					"%s: %v", msg, err)
				break
			}
		}
	}
}

type tstInput struct {
	txout              *wire.TxOut
	sigscriptGenerates bool
	inputValidates     bool
	indexOutOfRange    bool
}

type tstSigScript struct {
	name               string
	inputs             []tstInput
	hashType           SigHashType
	compress           bool
	scriptAtWrongIndex bool
}

var coinbaseOutPoint = &wire.OutPoint{
	Index: (1 << 32) - 1,
}

// 预生成的私钥，以及未压缩和压缩的 hash160 的关联公钥和 pkScript。
var (
	privKeyD = []byte{0x6b, 0x0f, 0xd8, 0xda, 0x54, 0x22, 0xd0, 0xb7,
		0xb4, 0xfc, 0x4e, 0x55, 0xd4, 0x88, 0x42, 0xb3, 0xa1, 0x65,
		0xac, 0x70, 0x7f, 0x3d, 0xa4, 0x39, 0x5e, 0xcb, 0x3b, 0xb0,
		0xd6, 0x0e, 0x06, 0x92}
	pubkeyX = []byte{0xb2, 0x52, 0xf0, 0x49, 0x85, 0x78, 0x03, 0x03, 0xc8,
		0x7d, 0xce, 0x51, 0x7f, 0xa8, 0x69, 0x0b, 0x91, 0x95, 0xf4,
		0xf3, 0x5c, 0x26, 0x73, 0x05, 0x05, 0xa2, 0xee, 0xbc, 0x09,
		0x38, 0x34, 0x3a}
	pubkeyY = []byte{0xb7, 0xc6, 0x7d, 0xb2, 0xe1, 0xff, 0xc8, 0x43, 0x1f,
		0x63, 0x32, 0x62, 0xaa, 0x60, 0xc6, 0x83, 0x30, 0xbd, 0x24,
		0x7e, 0xef, 0xdb, 0x6f, 0x2e, 0x8d, 0x56, 0xf0, 0x3c, 0x9f,
		0x6d, 0xb6, 0xf8}
	uncompressedPkScript = []byte{0x76, 0xa9, 0x14, 0xd1, 0x7c, 0xb5,
		0xeb, 0xa4, 0x02, 0xcb, 0x68, 0xe0, 0x69, 0x56, 0xbf, 0x32,
		0x53, 0x90, 0x0e, 0x0a, 0x86, 0xc9, 0xfa, 0x88, 0xac}
	compressedPkScript = []byte{0x76, 0xa9, 0x14, 0x27, 0x4d, 0x9f, 0x7f,
		0x61, 0x7e, 0x7c, 0x7a, 0x1c, 0x1f, 0xb2, 0x75, 0x79, 0x10,
		0x43, 0x65, 0x68, 0x27, 0x9d, 0x86, 0x88, 0xac}
	shortPkScript = []byte{0x76, 0xa9, 0x14, 0xd1, 0x7c, 0xb5,
		0xeb, 0xa4, 0x02, 0xcb, 0x68, 0xe0, 0x69, 0x56, 0xbf, 0x32,
		0x53, 0x90, 0x0e, 0x0a, 0x88, 0xac}
	uncompressedAddrStr = "1L6fd93zGmtzkK6CsZFVVoCwzZV3MUtJ4F"
	compressedAddrStr   = "14apLppt9zTq6cNw8SDfiJhk9PhkZrQtYZ"
)

// 假设输出量。
const coinbaseVal = 2500000000
const fee = 5000000

var sigScriptTests = []tstSigScript{
	{
		name: "one input uncompressed",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           false,
		scriptAtWrongIndex: false,
	},
	{
		name: "two inputs uncompressed",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
			{
				txout:              wire.NewTxOut(coinbaseVal+fee, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           false,
		scriptAtWrongIndex: false,
	},
	{
		name: "one input compressed",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, compressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           true,
		scriptAtWrongIndex: false,
	},
	{
		name: "two inputs compressed",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, compressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
			{
				txout:              wire.NewTxOut(coinbaseVal+fee, compressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           true,
		scriptAtWrongIndex: false,
	},
	{
		name: "hashType SigHashNone",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashNone,
		compress:           false,
		scriptAtWrongIndex: false,
	},
	{
		name: "hashType SigHashSingle",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashSingle,
		compress:           false,
		scriptAtWrongIndex: false,
	},
	{
		name: "hashType SigHashAnyoneCanPay",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAnyOneCanPay,
		compress:           false,
		scriptAtWrongIndex: false,
	},
	{
		name: "hashType non-standard",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           0x04,
		compress:           false,
		scriptAtWrongIndex: false,
	},
	{
		name: "invalid compression",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     false,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           true,
		scriptAtWrongIndex: false,
	},
	{
		name: "short PkScript",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, shortPkScript),
				sigscriptGenerates: false,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           false,
		scriptAtWrongIndex: false,
	},
	{
		name: "valid script at wrong index",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
			{
				txout:              wire.NewTxOut(coinbaseVal+fee, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           false,
		scriptAtWrongIndex: true,
	},
	{
		name: "index out of range",
		inputs: []tstInput{
			{
				txout:              wire.NewTxOut(coinbaseVal, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
			{
				txout:              wire.NewTxOut(coinbaseVal+fee, uncompressedPkScript),
				sigscriptGenerates: true,
				inputValidates:     true,
				indexOutOfRange:    false,
			},
		},
		hashType:           SigHashAll,
		compress:           false,
		scriptAtWrongIndex: true,
	},
}

// 测试 sigscript 生成的有效和无效输入、所有 hashType、以及是否有压缩。
// 该测试创建 sigscripts 来花费虚假的 coinbase 输入，因为无法为 txTests 中的 MsgTxs 创建 sigscripts，因为它们来自区块链并且我们没有私钥。
func TestSignatureScript(t *testing.T) {
	t.Parallel()

	privKey, _ := btcec.PrivKeyFromBytes(privKeyD)

nexttest:
	for i := range sigScriptTests {
		tx := wire.NewMsgTx(wire.TxVersion)

		output := wire.NewTxOut(500, []byte{OP_RETURN})
		tx.AddTxOut(output)

		for range sigScriptTests[i].inputs {
			txin := wire.NewTxIn(coinbaseOutPoint, nil, nil)
			tx.AddTxIn(txin)
		}

		var script []byte
		var err error
		for j := range tx.TxIn {
			var idx int
			if sigScriptTests[i].inputs[j].indexOutOfRange {
				t.Errorf("at test %v", sigScriptTests[i].name)
				idx = len(sigScriptTests[i].inputs)
			} else {
				idx = j
			}
			script, err = SignatureScript(tx, idx,
				sigScriptTests[i].inputs[j].txout.PkScript,
				sigScriptTests[i].hashType, privKey,
				sigScriptTests[i].compress)

			if (err == nil) != sigScriptTests[i].inputs[j].sigscriptGenerates {
				if err == nil {
					t.Errorf("passed test '%v' incorrectly",
						sigScriptTests[i].name)
				} else {
					t.Errorf("failed test '%v': %v",
						sigScriptTests[i].name, err)
				}
				continue nexttest
			}
			if !sigScriptTests[i].inputs[j].sigscriptGenerates {
				// 完成这个测试
				continue nexttest
			}

			tx.TxIn[j].SignatureScript = script
		}

		// 如果使用正确的 sigscript 进行测试但索引不正确，请使用最后一个输入脚本作为第一个输入。 需要 > 0 个输入进行测试。
		if sigScriptTests[i].scriptAtWrongIndex {
			tx.TxIn[0].SignatureScript = script
			sigScriptTests[i].inputs[0].inputValidates = false
		}

		// 验证 tx 输入脚本
		scriptFlags := ScriptBip16 | ScriptVerifyDERSignatures
		for j := range tx.TxIn {
			vm, err := NewEngine(sigScriptTests[i].
				inputs[j].txout.PkScript, tx, j, scriptFlags, nil, nil, 0, nil)
			if err != nil {
				t.Errorf("cannot create script vm for test %v: %v",
					sigScriptTests[i].name, err)
				continue nexttest
			}
			err = vm.Execute()
			if (err == nil) != sigScriptTests[i].inputs[j].inputValidates {
				if err == nil {
					t.Errorf("passed test '%v' validation incorrectly: %v",
						sigScriptTests[i].name, err)
				} else {
					t.Errorf("failed test '%v' validation: %v",
						sigScriptTests[i].name, err)
				}
				continue nexttest
			}
		}
	}
}

// TestRawTxInTaprootSignature 测试 RawTxInTaprootSignature 函数是否为所有相关的ighash类型生成有效签名。
func TestRawTxInTaprootSignature(t *testing.T) {
	t.Parallel()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	pubKey := ComputeTaprootKeyNoScript(privKey.PubKey())

	pkScript, err := PayToTaprootScript(pubKey)
	require.NoError(t, err)

	// 我们将在下面的测试中重用这个简单的事务。 它最终从 bip86 P2TR 输出中支出。
	testTx := wire.NewMsgTx(2)
	testTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: 1,
		},
	})
	txOut := &wire.TxOut{
		Value: 1e8, PkScript: pkScript,
	}
	testTx.AddTxOut(txOut)

	tests := []struct {
		sigHashType SigHashType
	}{
		{
			sigHashType: SigHashDefault,
		},
		{
			sigHashType: SigHashAll,
		},
		{
			sigHashType: SigHashNone,
		},
		{
			sigHashType: SigHashSingle,
		},
		{
			sigHashType: SigHashSingle | SigHashAnyOneCanPay,
		},
		{
			sigHashType: SigHashNone | SigHashAnyOneCanPay,
		},
		{
			sigHashType: SigHashAll | SigHashAnyOneCanPay,
		},
	}
	for _, test := range tests {
		name := fmt.Sprintf("sighash=%v", test.sigHashType)
		t.Run(name, func(t *testing.T) {
			prevFetcher := NewCannedPrevOutputFetcher(
				txOut.PkScript, txOut.Value,
			)
			sigHashes := NewTxSigHashes(testTx, prevFetcher)

			sig, err := RawTxInTaprootSignature(
				testTx, sigHashes, 0, txOut.Value, txOut.PkScript,
				nil, test.sigHashType, privKey,
			)
			require.NoError(t, err)

			// 如果这不是ighash默认值，那么应该应用sighash。 否则，它应该是一个正常的信号。
			expectedLen := schnorr.SignatureSize
			if test.sigHashType != SigHashDefault {
				expectedLen += 1
			}
			require.Len(t, sig, expectedLen)

			// 最后，确保生成的签名有效。
			txCopy := testTx.Copy()
			txCopy.TxIn[0].Witness = wire.TxWitness{sig}
			vm, err := NewEngine(
				txOut.PkScript, txCopy, 0, StandardVerifyFlags,
				nil, sigHashes, txOut.Value, prevFetcher,
			)
			require.NoError(t, err)

			require.NoError(t, vm.Execute())
		})
	}
}

// TestRawTxInTapscriptSignature 这就是说，我们能够为简单的 Tapscript 支出、各种 Sighash 类型生成有效的 schnorr 签名。
func TestRawTxInTapscriptSignature(t *testing.T) {
	t.Parallel()

	privKey, err := btcec.NewPrivateKey()
	require.NoError(t, err)

	internalKey := privKey.PubKey()

	// 我们的脚本将是一个简单的 OP_CHECKSIG 作为 Tapscript 树的唯一叶子。 我们还将重新使用内部密钥作为叶子中的密钥。
	builder := NewScriptBuilder()
	builder.AddData(schnorr.SerializePubKey(internalKey))
	builder.AddOp(OP_CHECKSIG)
	pkScript, err := builder.Script()
	require.NoError(t, err)

	tapLeaf := NewBaseTapLeaf(pkScript)
	tapScriptTree := AssembleTaprootScriptTree(tapLeaf)

	ctrlBlock := tapScriptTree.LeafMerkleProofs[0].ToControlBlock(
		internalKey,
	)

	tapScriptRootHash := tapScriptTree.RootNode.TapHash()
	outputKey := ComputeTaprootOutputKey(
		internalKey, tapScriptRootHash[:],
	)
	p2trScript, err := PayToTaprootScript(outputKey)
	require.NoError(t, err)

	// 我们将在下面的测试中重用这个简单的事务。 它最终从 bip86 P2TR 输出中支出。
	testTx := wire.NewMsgTx(2)
	testTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Index: 1,
		},
	})
	txOut := &wire.TxOut{
		Value: 1e8, PkScript: p2trScript,
	}
	testTx.AddTxOut(txOut)

	tests := []struct {
		sigHashType SigHashType
	}{
		{
			sigHashType: SigHashDefault,
		},
		{
			sigHashType: SigHashAll,
		},
		{
			sigHashType: SigHashNone,
		},
		{
			sigHashType: SigHashSingle,
		},
		{
			sigHashType: SigHashSingle | SigHashAnyOneCanPay,
		},
		{
			sigHashType: SigHashNone | SigHashAnyOneCanPay,
		},
		{
			sigHashType: SigHashAll | SigHashAnyOneCanPay,
		},
	}
	for _, test := range tests {
		name := fmt.Sprintf("sighash=%v", test.sigHashType)
		t.Run(name, func(t *testing.T) {
			prevFetcher := NewCannedPrevOutputFetcher(
				txOut.PkScript, txOut.Value,
			)
			sigHashes := NewTxSigHashes(testTx, prevFetcher)

			sig, err := RawTxInTapscriptSignature(
				testTx, sigHashes, 0, txOut.Value,
				txOut.PkScript, tapLeaf, test.sigHashType,
				privKey,
			)
			require.NoError(t, err)

			// 如果这不是ighash默认值，那么应该应用sighash。 否则，它应该是一个正常的信号。
			expectedLen := schnorr.SignatureSize
			if test.sigHashType != SigHashDefault {
				expectedLen += 1
			}
			require.Len(t, sig, expectedLen)

			// 现在我们有了签名，我们将创建一个有效的见证人，包括控制块。
			ctrlBlockBytes, err := ctrlBlock.ToBytes()
			require.NoError(t, err)
			txCopy := testTx.Copy()
			txCopy.TxIn[0].Witness = wire.TxWitness{
				sig, pkScript, ctrlBlockBytes,
			}

			// 最后，确保生成的签名有效。
			vm, err := NewEngine(
				txOut.PkScript, txCopy, 0, StandardVerifyFlags,
				nil, sigHashes, txOut.Value, prevFetcher,
			)
			require.NoError(t, err)

			require.NoError(t, vm.Execute())
		})
	}
}
