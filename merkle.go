package bpfschain

import (
	"crypto/sha256"

	"github.com/sirupsen/logrus"
)

// MerkleTree 代表一个 Merkle 树
type MerkleTree struct {
	RootNode *MerkleNode
}

// MerkleNode 代表一个 Merkle 树节点
type MerkleNode struct {
	Left  *MerkleNode
	Right *MerkleNode
	Data  []byte
}

// NewMerkleNode 创建一个新的 Merkle 树节点
func NewMerkleNode(left, right *MerkleNode, data []byte) *MerkleNode {
	node := &MerkleNode{
		Left:  left,
		Right: right,
	}

	if left == nil && right == nil {
		// 如果是叶子节点，直接使用数据的哈希
		hash := sha256.Sum256(data)
		node.Data = hash[:]
	} else {
		// 如果不是叶子节点，将左右子节点的数据合并后哈希
		prevHashes := append(left.Data, right.Data...)
		hash := sha256.Sum256(prevHashes)
		node.Data = hash[:]
	}

	return node
}

// NewMerkleTree 从数据序列创建一个新的 Merkle 树
func NewMerkleTree(data [][]byte) *MerkleTree {

	var nodes []MerkleNode

	// 创建叶节点
	for _, d := range data {
		node := NewMerkleNode(nil, nil, d)
		nodes = append(nodes, *node)
	}

	if len(nodes) == 0 {
		logrus.Panic("No merkle Tree node")
	}

	// 创建父节点
	for len(nodes) > 1 {
		// 叶节点的长度必须是偶数
		if len(nodes)%2 != 0 {
			// 将最后一个节点复制一份并加入到叶子节点列表中
			dupNode := nodes[len(nodes)-1]
			nodes = append(nodes, dupNode)
		}

		var level []MerkleNode
		for i := 0; i < len(nodes); i += 2 {
			node := NewMerkleNode(&nodes[i], &nodes[i+1], nil)
			level = append(level, *node)
		}

		nodes = level
	}

	tree := MerkleTree{&nodes[0]}

	return &tree
}
