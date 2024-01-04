// 包含处理 Taproot 相关脚本逻辑的代码，Taproot 是比特币协议的一个较新的升级。

package txscript

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TapscriptLeafVersion 表示 tapscript leaf 版本的各种可能版本。叶子版本用于在基本的 taproot 执行模型下定义或引入新的脚本语义。
//
// TODO(roasbeef)：在这里添加验证，例如适当的前缀等？
type TapscriptLeafVersion uint8

const (
	// BaseLeafVersion 是基本的 tapscript leaf 版本。该版本的 该版本的语义已在 BIP 342 中定义。
	BaseLeafVersion TapscriptLeafVersion = 0xc0
)

const (
	// ControlBlockBaseSize 是控制块的基本尺寸。它
	// 包括叶子版本的初始字节和序列化的 schnorr 公钥。
	ControlBlockBaseSize = 33

	// ControlBlockNodeSize 是控制块中给定梅克尔分支哈希值的大小。
	ControlBlockNodeSize = 32

	// ControlBlockMaxNodeCount 是控制块中可包含的最大节点数。 节点数。该值表示一棵深度为 2^128 的梅克尔树。
	ControlBlockMaxNodeCount = 128

	// ControlBlockMaxSize 是控制块的最大可能大小。 这将模拟从最大可能的 tapscript 树中揭示一片叶子。
	ControlBlockMaxSize = ControlBlockBaseSize + (ControlBlockNodeSize *
		ControlBlockMaxNodeCount)
)

// VerifyTaprootKeySpend 试图验证顶级分根密钥，如果传递的签名无效，
// 则返回非零错误。 如果传入了 sigCache，则会查询 sig 缓存，
// 以跳过对已看过的签名的全面验证。这里的见证程序应该是 32 字节 x-only schnorr 输出公钥。
//
// 注意：TxSigHashes 必须传入并完全填充。
func VerifyTaprootKeySpend(witnessProgram []byte, rawSig []byte, tx *wire.MsgTx,
	inputIndex int, prevOuts PrevOutputFetcher, hashCache *TxSigHashes,
	sigCache *SigCache) error {

	// First, we'll need to extract the public key from the witness
	// program.
	rawKey := witnessProgram

	// Extract the annex if it exists, so we can compute the proper proper
	// sighash below.
	var annex []byte
	witness := tx.TxIn[inputIndex].Witness
	if isAnnexedWitness(witness) {
		annex, _ = extractAnnex(witness)
	}

	// Now that we have the public key, we can create a new top-level
	// keyspend verifier that'll handle all the sighash and schnorr
	// specifics for us.
	keySpendVerifier, err := newTaprootSigVerifier(
		rawKey, rawSig, tx, inputIndex, prevOuts, sigCache,
		hashCache, annex,
	)
	if err != nil {
		return err
	}

	valid := keySpendVerifier.Verify()
	if valid {
		return nil
	}

	return scriptError(ErrTaprootSigInvalid, "")
}

// 控制块（ControlBlock）包含用于分根花费的结构化见证输入。其中包括内部分根密钥、叶子版本，最后是主分根承诺的近乎完整的梅克尔包含证明。
//
// TODO(roasbeef)：序列化控制块的方法，该控制块提交到偶数 Y 位，即使 32 字节密钥也会到处出现。
type ControlBlock struct {
	// InternalKey is the internal public key in the taproot commitment.
	InternalKey *btcec.PublicKey

	// OutputKeyYIsOdd denotes if the y coordinate of the output key (the
	// key placed in the actual taproot output is odd.
	OutputKeyYIsOdd bool

	// LeafVersion is the specified leaf version of the tapscript leaf that
	// the InclusionProof below is based off of.
	LeafVersion TapscriptLeafVersion

	// InclusionProof is a series of merkle branches that when hashed
	// pairwise, starting with the revealed script, will yield the taproot
	// commitment root.
	InclusionProof []byte
}

// ToBytes 返回的控制块格式适合用作 见证输出的格式返回控制块。
func (c *ControlBlock) ToBytes() ([]byte, error) {
	var b bytes.Buffer

	// The first byte of the control block is the leaf version byte XOR'd with
	// the parity of the y coordinate of the public key.
	yParity := byte(0)
	if c.OutputKeyYIsOdd {
		yParity = 1
	}

	// The first byte is a combination of the leaf version, using the lowest
	// bit to encode the single bit that denotes if the yo coordinate if odd or
	// even.
	leafVersionAndParity := byte(c.LeafVersion) | yParity
	if err := b.WriteByte(leafVersionAndParity); err != nil {
		return nil, err
	}

	// Next, we encode the raw 32 byte schnorr public key
	if _, err := b.Write(schnorr.SerializePubKey(c.InternalKey)); err != nil {
		return nil, err
	}

	// Finally, we'll write out the inclusion proof as is, without any length
	// prefix.
	if _, err := b.Write(c.InclusionProof); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// RootHash 会根据显示的脚本计算 taps 脚本的根哈希值。
func (c *ControlBlock) RootHash(revealedScript []byte) []byte {
	// We'll start by creating a new tapleaf from the revealed script,
	// this'll serve as the initial hash we'll use to incrementally
	// reconstruct the merkle root using the control block elements.
	merkleAccumulator := NewTapLeaf(c.LeafVersion, revealedScript).TapHash()

	// Now that we have our initial hash, we'll parse the control block one
	// node at a time to build up our merkle accumulator into the taproot
	// commitment.
	//
	// The control block is a series of nodes that serve as an inclusion
	// proof as we can start hashing with our leaf, with each internal
	// branch, until we reach the root.
	numNodes := len(c.InclusionProof) / ControlBlockNodeSize
	for nodeOffset := 0; nodeOffset < numNodes; nodeOffset++ {
		// Extract the new node using our index to serve as a 32-byte
		// offset.
		leafOffset := 32 * nodeOffset
		nextNode := c.InclusionProof[leafOffset : leafOffset+32]

		merkleAccumulator = tapBranchHash(merkleAccumulator[:], nextNode)
	}

	return merkleAccumulator[:]
}

// ParseControlBlock 试图解析控制块的原始字节。如果控制块不完整或无法解析，将返回错误信息。
func ParseControlBlock(ctrlBlock []byte) (*ControlBlock, error) {
	// The control block minimally must contain 33 bytes (for the leaf
	// version and internal key) along with at least a single value
	// comprising the merkle proof. If not, then it's invalid.
	switch {
	// The control block must minimally have 33 bytes for the internal
	// public key and script leaf version.
	case len(ctrlBlock) < ControlBlockBaseSize:
		str := fmt.Sprintf("min size is %v bytes, control block "+
			"is %v bytes", ControlBlockBaseSize, len(ctrlBlock))
		return nil, scriptError(ErrControlBlockTooSmall, str)

	// The control block can't be larger than a proof for the largest
	// possible tapscript merkle tree with 2^128 leaves.
	case len(ctrlBlock) > ControlBlockMaxSize:
		str := fmt.Sprintf("max size is %v, control block is %v bytes",
			ControlBlockMaxSize, len(ctrlBlock))
		return nil, scriptError(ErrControlBlockTooLarge, str)

	// Ignoring the fixed sized portion, we expect the total number of
	// remaining bytes to be a multiple of the node size, which is 32
	// bytes.
	case (len(ctrlBlock)-ControlBlockBaseSize)%ControlBlockNodeSize != 0:
		str := fmt.Sprintf("control block proof is not a multiple "+
			"of 32: %v", len(ctrlBlock)-ControlBlockBaseSize)
		return nil, scriptError(ErrControlBlockInvalidLength, str)
	}

	// With the basic sanity checking complete, we can now parse the
	// control block.
	leafVersion := TapscriptLeafVersion(ctrlBlock[0] & TaprootLeafMask)

	// Extract the parity of the y coordinate of the internal key.
	var yIsOdd bool
	if ctrlBlock[0]&0x01 == 0x01 {
		yIsOdd = true
	}

	// Next, we'll parse the public key, which is the 32 bytes following
	// the leaf version.
	rawKey := ctrlBlock[1:33]
	pubKey, err := schnorr.ParsePubKey(rawKey)
	if err != nil {
		return nil, err
	}

	// The rest of the bytes are the control block itself, which encodes a
	// merkle proof of inclusion.
	proofBytes := ctrlBlock[33:]

	return &ControlBlock{
		InternalKey:     pubKey,
		OutputKeyYIsOdd: yIsOdd,
		LeafVersion:     leafVersion,
		InclusionProof:  proofBytes,
	}, nil
}

// ComputeTaprootOutputKey 在给定内部密钥和 tapscript merkle 根的情况下计算顶级分根输出密钥。
// 最终密钥的计算公式为：taprootKey = internalKey + (h_tapTweak(internalKey || merkleRoot)*G).
func ComputeTaprootOutputKey(pubKey *btcec.PublicKey,
	scriptRoot []byte) *btcec.PublicKey {

	// This routine only operates on x-only public keys where the public
	// key always has an even y coordinate, so we'll re-parse it as such.
	internalKey, _ := schnorr.ParsePubKey(schnorr.SerializePubKey(pubKey))

	// First, we'll compute the tap tweak hash that commits to the internal
	// key and the merkle script root.
	tapTweakHash := chainhash.TaggedHash(
		chainhash.TagTapTweak, schnorr.SerializePubKey(internalKey),
		scriptRoot,
	)

	// With the tap tweek computed,  we'll need to convert the merkle root
	// into something in the domain we can manipulate: a scalar value mod
	// N.
	var tweakScalar btcec.ModNScalar
	tweakScalar.SetBytes((*[32]byte)(tapTweakHash))

	// Next, we'll need to convert the internal key to jacobian coordinates
	// as the routines we need only operate on this type.
	var internalPoint btcec.JacobianPoint
	internalKey.AsJacobian(&internalPoint)

	// With our intermediate data obtained, we'll now compute:
	//
	// taprootKey = internalPoint + (tapTweak*G).
	var tPoint, taprootKey btcec.JacobianPoint
	btcec.ScalarBaseMultNonConst(&tweakScalar, &tPoint)
	btcec.AddNonConst(&internalPoint, &tPoint, &taprootKey)

	// Finally, we'll convert the key back to affine coordinates so we can
	// return the format of public key we usually use.
	taprootKey.ToAffine()

	return btcec.NewPublicKey(&taprootKey.X, &taprootKey.Y)
}

// ComputeTaprootKeyNoScript 在给定内部密钥的情况下计算顶层分根输出密钥，
// 并希望输出密钥的唯一使用方式是使用 keypend 路径。这对正常的钱包操作非常有用，因为 不需要其他额外支出条件。
func ComputeTaprootKeyNoScript(internalKey *btcec.PublicKey) *btcec.PublicKey {
	// We'll compute a custom tap tweak hash that just commits to the key,
	// rather than an actual root hash.
	fakeScriptroot := []byte{}

	return ComputeTaprootOutputKey(internalKey, fakeScriptroot)
}

// TweakTaprootPrivKey 采用了与 ComputeTaprootOutputKey 相同的操作，
// 不过是在私钥上。最终密钥的计算公式为：PrivKey + h_tapTweak(internalKey || merkleRoot) % N，
// 其中 N 是 secp256k1 曲线的阶数，merkleRoot 是 tapscript 树的根哈希值。
func TweakTaprootPrivKey(privKey btcec.PrivateKey,
	scriptRoot []byte) *btcec.PrivateKey {

	// If the corresponding public key has an odd y coordinate, then we'll
	// negate the private key as specified in BIP 341.
	privKeyScalar := privKey.Key
	pubKeyBytes := privKey.PubKey().SerializeCompressed()
	if pubKeyBytes[0] == secp.PubKeyFormatCompressedOdd {
		privKeyScalar.Negate()
	}

	// Next, we'll compute the tap tweak hash that commits to the internal
	// key and the merkle script root. We'll snip off the extra parity byte
	// from the compressed serialization and use that directly.
	schnorrKeyBytes := pubKeyBytes[1:]
	tapTweakHash := chainhash.TaggedHash(
		chainhash.TagTapTweak, schnorrKeyBytes, scriptRoot,
	)

	// Map the private key to a ModNScalar which is needed to perform
	// operation mod the curve order.
	var tweakScalar btcec.ModNScalar
	tweakScalar.SetBytes((*[32]byte)(tapTweakHash))

	// Now that we have the private key in its may negated form, we'll add
	// the script root as a tweak. As we're using a ModNScalar all
	// operations are already normalized mod the curve order.
	privTweak := privKeyScalar.Add(&tweakScalar)

	return btcec.PrivKeyFromScalar(privTweak)
}

// VerifyTaprootLeafCommitment 试图验证 taprootWitnessProgram（一个 schnorr 公钥）中所揭示脚本的 taproot 承诺。
// 如果重建的分根承诺（梅克尔根和内部密钥的函数）与传递的见证程序不匹配，则返回错误信息。
func VerifyTaprootLeafCommitment(controlBlock *ControlBlock,
	taprootWitnessProgram []byte, revealedScript []byte) error {

	// First, we'll calculate the root hash from the given proof and
	// revealed script.
	rootHash := controlBlock.RootHash(revealedScript)

	// Next, we'll construct the final commitment (creating the external or
	// taproot output key) as a function of this commitment and the
	// included internal key: taprootKey = internalKey + (tPoint*G).
	taprootKey := ComputeTaprootOutputKey(
		controlBlock.InternalKey, rootHash,
	)

	// If we convert the taproot key to a witness program (we just need to
	// serialize the public key), then it should exactly match the witness
	// program passed in.
	expectedWitnessProgram := schnorr.SerializePubKey(taprootKey)
	if !bytes.Equal(expectedWitnessProgram, taprootWitnessProgram) {

		return scriptError(ErrTaprootMerkleProofInvalid, "")
	}

	// Finally, we'll verify that the parity of the y coordinate of the
	// public key we've derived matches the control block.
	derivedYIsOdd := (taprootKey.SerializeCompressed()[0] ==
		secp.PubKeyFormatCompressedOdd)
	if controlBlock.OutputKeyYIsOdd != derivedYIsOdd {
		str := fmt.Sprintf("control block y is odd: %v, derived "+
			"parity is odd: %v", controlBlock.OutputKeyYIsOdd,
			derivedYIsOdd)
		return scriptError(ErrTaprootOutputKeyParityMismatch, str)
	}

	// Otherwise, if we reach here, the commitment opening is valid and
	// execution can continue.
	return nil
}

// TapNode 表示 tapscript 梅克尔树中的一个抽象节点。节点 分支或叶子。
type TapNode interface {
	// TapHash returns the hash of the node. This will either be a tagged
	// hash derived from a branch, or a leaf.
	TapHash() chainhash.Hash

	// Left returns the left node. If this is a leaf node, this may be nil.
	Left() TapNode

	// Right returns the right node. If this is a leaf node, this may be
	// nil.
	Right() TapNode
}

// TapLeaf 表示 tapscript 树中的一片叶子。叶子有两个组成部分： 叶子版本，以及与该叶子版本相关联的脚本。
type TapLeaf struct {
	// LeafVersion is the leaf version of this leaf.
	LeafVersion TapscriptLeafVersion

	// Script is the script to be validated based on the specified leaf
	// version.
	Script []byte
}

// 左节点为该叶子的左节点。由于这是一片叶子，所以左节点为 nil。
func (t TapLeaf) Left() TapNode {
	return nil
}

// 叶的右节点。由于这是一个叶节点，所以右节点 为零。
func (t TapLeaf) Right() TapNode {
	return nil
}

// NewBaseTapLeaf 返回指定脚本的新 TapLeaf，使用 当前的基叶版本（BIP 342）。
func NewBaseTapLeaf(script []byte) TapLeaf {
	return TapLeaf{
		Script:      script,
		LeafVersion: BaseLeafVersion,
	}
}

// NewTapLeaf 返回一个新的 TapLeaf，该 TapLeaf 包含给定的叶子版本和脚本。脚本的新 TapLeaf。
func NewTapLeaf(leafVersion TapscriptLeafVersion, script []byte) TapLeaf {
	return TapLeaf{
		LeafVersion: leafVersion,
		Script:      script,
	}
}

// NewTapLeaf 返回一个新的 TapLeaf，该 TapLeaf 包含给定的叶子版本和脚本。脚本的新 TapLeaf。
func (t TapLeaf) TapHash() chainhash.Hash {
	// TODO(roasbeef): cache these and the branch due to the recursive
	// call, so memoize

	// The leaf encoding is: leafVersion || compactSizeof(script) ||
	// script, where compactSizeof returns the compact size needed to
	// encode the value.
	var leafEncoding bytes.Buffer

	_ = leafEncoding.WriteByte(byte(t.LeafVersion))
	_ = wire.WriteVarBytes(&leafEncoding, 0, t.Script)

	return *chainhash.TaggedHash(chainhash.TagTapLeaf, leafEncoding.Bytes())
}

// TapBranch 表示 tapscript 树中的一个内部分支。左边或右边的节点可以是另一个分支、叶子或两者的组合。
type TapBranch struct {
	// leftNode is the left node, this cannot be nil.
	leftNode TapNode

	// rightNode is the right node, this cannot be nil.
	rightNode TapNode
}

// NewTapBranch 从左右节点创建新的内部分支。
func NewTapBranch(l, r TapNode) TapBranch {

	return TapBranch{
		leftNode:  l,
		rightNode: r,
	}
}

// 左节点是分支的左节点，可能是叶节点，也可能是另一个分支。
func (t TapBranch) Left() TapNode {
	return t.leftNode
}

// 右节点是一个分支的右节点，可能是一片叶子，也可能是另一个分支。
func (t TapBranch) Right() TapNode {
	return t.rightNode
}

// TapHash 返回给定左节点和右节点的分根内部分支的哈希摘要。最终的哈希摘要为：
// h_tapbranch(leftNode || rightNode)，其中 leftNode 是这两个节点中按词序排列的较小节点。
func (t TapBranch) TapHash() chainhash.Hash {
	leftHash := t.leftNode.TapHash()
	rightHash := t.rightNode.TapHash()
	return tapBranchHash(leftHash[:], rightHash[:])
}

// tapBranchHash 获取左右节点的原始分接散列，并将其散列成一个分支。具体请参阅 TapBranch 方法。
func tapBranchHash(l, r []byte) chainhash.Hash {
	if bytes.Compare(l[:], r[:]) > 0 {
		l, r = r, l
	}

	return *chainhash.TaggedHash(
		chainhash.TagTapBranch, l[:], r[:],
	)
}

// TapscriptProof 是一种包含证明，证明给定的叶（脚本和叶版本）包含在顶级 taproot 输出承诺中。
type TapscriptProof struct {
	// TapLeaf is the leaf that we want to prove inclusion for.
	TapLeaf

	// RootNode is the root of the tapscript tree, this will be used to
	// compute what the final output key looks like.
	RootNode TapNode

	// InclusionProof is the tail end of the control block that contains
	// the series of hashes (the sibling hashes up the tree), that when
	// hashed together allow us to re-derive the top level taproot output.
	InclusionProof []byte
}

// ToControlBlock 会将 tapscript 证明映射到一个完全有效的控制块中。可用作 tapscript 支出的见证项。
func (t *TapscriptProof) ToControlBlock(internalKey *btcec.PublicKey) ControlBlock {
	// Compute the total level output commitment based on the populated
	// root node.
	rootHash := t.RootNode.TapHash()
	taprootKey := ComputeTaprootOutputKey(
		internalKey, rootHash[:],
	)

	// With the commitment computed we can obtain the bit that denotes if
	// the resulting key has an odd y coordinate or not.
	var outputKeyYIsOdd bool
	if taprootKey.SerializeCompressed()[0] ==
		secp.PubKeyFormatCompressedOdd {

		outputKeyYIsOdd = true
	}

	return ControlBlock{
		InternalKey:     internalKey,
		OutputKeyYIsOdd: outputKeyYIsOdd,
		LeafVersion:     t.TapLeaf.LeafVersion,
		InclusionProof:  t.InclusionProof,
	}
}

// IndexedTapScriptTree 重印了一棵完全收缩的 Tapscript 树。索引的 根节点可用于向下遍历整棵树。
// 此外，还包括每个叶子的完整包含证明，并根据给定叶子的 tap leaf 哈希值为证明片段提供索引。
type IndexedTapScriptTree struct {
	// RootNode is the root of the tapscript tree. RootNode.TapHash() can
	// be used to extract the hash needed to derive the taptweak committed
	// to in the taproot output.
	RootNode TapNode

	// LeafMerkleProofs is a slice that houses the series of merkle
	// inclusion proofs for each leaf based on the input order of the
	// leaves.
	LeafMerkleProofs []TapscriptProof

	// LeafProofIndex maps the TapHash() of a given leaf node to the index
	// within the LeafMerkleProofs array above. This can be used to
	// retrieve the inclusion proof for a given script when constructing
	// the witness stack and control block for spending a tapscript path.
	LeafProofIndex map[chainhash.Hash]int
}

// NewIndexedTapScriptTree 会创建一棵新的空 tapscript 树，该树有足够的 空间来保存指定数量的树叶信息。
func NewIndexedTapScriptTree(numLeaves int) *IndexedTapScriptTree {
	return &IndexedTapScriptTree{
		LeafMerkleProofs: make([]TapscriptProof, numLeaves),
		LeafProofIndex:   make(map[chainhash.Hash]int, numLeaves),
	}
}

// hashTapNodes 接收左右两个节点，然后返回左右两个节点的哈希值以及新的合并节点。如果两个节点都为 nil，
// 则返回 nil 指针。如果右边的 now 为空，则传入左边的节点，只要该节点没有任何同级节点，就会有效地将其在树中 "提升"。
func hashTapNodes(left, right TapNode) (*chainhash.Hash, *chainhash.Hash, TapNode) {
	switch {
	// If there's no left child, then this is a "nil" portion of the array
	// tree, so well thread thru nil.
	case left == nil:
		return nil, nil, nil

	// If there's no right child, then this is a single node that'll be
	// passed all the way up the tree as it has no children.
	case right == nil:
		return nil, nil, left
	}

	// The result of hashing two nodes will always be a branch, so we start
	// with that.
	leftHash := left.TapHash()
	rightHash := right.TapHash()

	return &leftHash, &rightHash, NewTapBranch(left, right)
}

// leafDescendants 是一种递归算法，
// 用于返回作为该树的后代的所有叶节点。的叶子节点。我们每次向上移动树时，都需要用它来收集一系列节点，以扩展包含证明。
func leafDescendants(node TapNode) []TapNode {
	// A leaf node has no decedents, so we just return it directly.
	if node.Left() == nil && node.Right() == nil {
		return []TapNode{node}
	}

	// Otherwise, get the descendants of the left and right sub-trees to
	// return.
	leftLeaves := leafDescendants(node.Left())
	rightLeaves := leafDescendants(node.Right())

	return append(leftLeaves, rightLeaves...)
}

// AssembleTaprootScriptTree 在给定一系列叶子节点的情况下，构建一棵新的完全索引的
// tapscript 树。它结合了递归数据结构和基于数组的表示方法，既能生成树，
// 又能在同一路径上积累所有必要的包含证明。更多详情，请参阅 blockchain.BuildMerkleTreeStore 的注释。
func AssembleTaprootScriptTree(leaves ...TapLeaf) *IndexedTapScriptTree {
	// If there's only a single leaf, then that becomes our root.
	if len(leaves) == 1 {
		// A lone leaf has no additional inclusion proof, as a verifier
		// will just hash the leaf as the sole branch.
		leaf := leaves[0]
		return &IndexedTapScriptTree{
			RootNode: leaf,
			LeafProofIndex: map[chainhash.Hash]int{
				leaf.TapHash(): 0,
			},
			LeafMerkleProofs: []TapscriptProof{
				{
					TapLeaf:        leaf,
					RootNode:       leaf,
					InclusionProof: nil,
				},
			},
		}
	}

	// We'll start out by populating the leaf index which maps a leave's
	// taphash to its index within the tree.
	scriptTree := NewIndexedTapScriptTree(len(leaves))
	for i, leaf := range leaves {
		leafHash := leaf.TapHash()
		scriptTree.LeafProofIndex[leafHash] = i
	}

	var branches []TapBranch
	for i := 0; i < len(leaves); i += 2 {
		// If there's only a single leaf left, then we'll merge this
		// with the last branch we have.
		if i == len(leaves)-1 {
			branchToMerge := branches[len(branches)-1]
			leaf := leaves[i]
			newBranch := NewTapBranch(branchToMerge, leaf)

			branches[len(branches)-1] = newBranch

			// The leaf includes the existing branch within its
			// inclusion proof.
			branchHash := branchToMerge.TapHash()

			scriptTree.LeafMerkleProofs[i].TapLeaf = leaf
			scriptTree.LeafMerkleProofs[i].InclusionProof = append(
				scriptTree.LeafMerkleProofs[i].InclusionProof,
				branchHash[:]...,
			)

			// We'll also add this right hash to the inclusion of
			// the left and right nodes of the branch.
			lastLeafHash := leaf.TapHash()

			leftLeafHash := branchToMerge.Left().TapHash()
			leftLeafIndex := scriptTree.LeafProofIndex[leftLeafHash]
			scriptTree.LeafMerkleProofs[leftLeafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[leftLeafIndex].InclusionProof,
				lastLeafHash[:]...,
			)

			rightLeafHash := branchToMerge.Right().TapHash()
			rightLeafIndex := scriptTree.LeafProofIndex[rightLeafHash]
			scriptTree.LeafMerkleProofs[rightLeafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[rightLeafIndex].InclusionProof,
				lastLeafHash[:]...,
			)

			continue
		}

		// While we still have leaves left, we'll combine two of them
		// into a new branch node.
		left, right := leaves[i], leaves[i+1]
		nextBranch := NewTapBranch(left, right)
		branches = append(branches, nextBranch)

		// The left node will use the right node as part of its
		// inclusion proof, and vice versa.
		leftHash := left.TapHash()
		rightHash := right.TapHash()

		scriptTree.LeafMerkleProofs[i].TapLeaf = left
		scriptTree.LeafMerkleProofs[i].InclusionProof = append(
			scriptTree.LeafMerkleProofs[i].InclusionProof,
			rightHash[:]...,
		)

		scriptTree.LeafMerkleProofs[i+1].TapLeaf = right
		scriptTree.LeafMerkleProofs[i+1].InclusionProof = append(
			scriptTree.LeafMerkleProofs[i+1].InclusionProof,
			leftHash[:]...,
		)
	}

	// In this second phase, we'll merge all the leaf branches we have one
	// by one until we have our final root.
	var rootNode TapNode
	for len(branches) != 0 {
		// When we only have a single branch left, then that becomes
		// our root.
		if len(branches) == 1 {
			rootNode = branches[0]
			break
		}

		left, right := branches[0], branches[1]

		newBranch := NewTapBranch(left, right)

		branches = branches[2:]

		branches = append(branches, newBranch)

		// Accumulate the sibling hash of this new branch for all the
		// leaves that are its children.
		leftLeafDescendants := leafDescendants(left)
		rightLeafDescendants := leafDescendants(right)

		leftHash, rightHash := left.TapHash(), right.TapHash()

		// For each left hash that's a leaf descendants, well add the
		// right sibling as that sibling is needed to construct the new
		// internal branch we just created. We also do the same for the
		// siblings of the right node.
		for _, leftLeaf := range leftLeafDescendants {
			leafHash := leftLeaf.TapHash()
			leafIndex := scriptTree.LeafProofIndex[leafHash]

			scriptTree.LeafMerkleProofs[leafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[leafIndex].InclusionProof,
				rightHash[:]...,
			)
		}
		for _, rightLeaf := range rightLeafDescendants {
			leafHash := rightLeaf.TapHash()
			leafIndex := scriptTree.LeafProofIndex[leafHash]

			scriptTree.LeafMerkleProofs[leafIndex].InclusionProof = append(
				scriptTree.LeafMerkleProofs[leafIndex].InclusionProof,
				leftHash[:]...,
			)
		}
	}

	// Populate the top level root node pointer, as well as the pointer in
	// each proof.
	scriptTree.RootNode = rootNode
	for i := range scriptTree.LeafMerkleProofs {
		scriptTree.LeafMerkleProofs[i].RootNode = rootNode
	}

	return scriptTree
}

// PayToTaprootScript 会创建一个 pk 脚本，用于输出付费点根密钥。
func PayToTaprootScript(taprootKey *btcec.PublicKey) ([]byte, error) {
	return NewScriptBuilder().
		AddOp(OP_1).
		AddData(schnorr.SerializePubKey(taprootKey)).
		Script()
}
