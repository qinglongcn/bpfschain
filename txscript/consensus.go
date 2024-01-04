// 包含与比特币共识规则相关的脚本验证逻辑。

package txscript

const (
	// LockTimeThreshold 是一个数字，低于该数字锁定时间将被解释为块号。
	// 由于平均每 10 分钟生成一个区块，因此区块的寿命约为 9,512 年。
	LockTimeThreshold = 5e8 // 世界标准时间 1985 年 11 月 5 日星期二 00:53:20
)
