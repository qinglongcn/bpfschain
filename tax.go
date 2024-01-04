package bpfschain

import (
	"math/big"
	"time"
)

// CalculateTransactionCost 计算交易费用
// 这个函数计算基于交易金额的费用，费用是交易金额的0.3%
func CalculateTransactionCost(amount float64) float64 {
	return amount * txCost // 0.3% 的交易额
}

// //////////////////////////////////////////////////////
// 增值税率区间和相应的税率
type CapitalGainsTaxRate struct {
	LowerBound float64 // 增值下界
	UpperBound float64 // 增值上界
	Rate       float64 // 对应的税率
}

// 增值税率表
var CapitalGainsTaxRates = []CapitalGainsTaxRate{
	{0, 0.1, 0.03},   // 0% 到 10% 的增值，税率是 3%
	{0.1, 0.2, 0.1},  // 10% 到 20% 的增值，税率是 10%
	{0.2, 0.3, 0.2},  // 20% 到 30% 的增值，税率是 20%
	{0.3, 0.4, 0.25}, // 30% 到 40% 的增值，税率是 25%
	{0.4, 0.5, 0.3},  // 40% 到 50% 的增值，税率是 30%
	{0.5, 1, 0.35},   // 50% 到 100% 的增值，税率是 35%
	{1, -1, 0.45},    // 超过 100% 的增值，税率是 45%
}

// 计算增值税的函数
func CalculateCapitalGainsTax(OriginalTransactionValue, currentTransactionValue float64) float64 {
	// 计算增值
	gain := currentTransactionValue - OriginalTransactionValue
	if gain <= 0 { // 没有增值
		return 0
	}

	// 计算对应的税率
	var rate float64
	for _, taxRate := range CapitalGainsTaxRates {
		if gain > taxRate.LowerBound && gain <= taxRate.UpperBound {
			rate = taxRate.Rate
			break
		}
	}

	// 计算增值税
	capitalGainsTax := gain * rate
	return capitalGainsTax
}

////////////////////////////////////////////////////////

// CalculateStorageCost 计算文件存储的费用
// 根据文件的大小、存储时间和 Gas 价格来计算存储费用
func CalculateStorageCost(fileSize int64, storageTime time.Duration, gasPrice int) *big.Int {
	totalGas := big.NewInt(fileSize).Mul(big.NewInt(fileSize), big.NewInt(int64(storageTime.Seconds())))
	return new(big.Int).Mul(totalGas, big.NewInt(int64(gasPrice)))
}

// 动态计算 GasPrice
func CalculateDynamicGasPrice(
	totalStorage int64,
	usedStorage int64,
	fileSize int64,
	storageTime time.Duration,
	networkCongestion float64) *big.Int {

	// 计算存储使用率
	storageUsageRate := float64(usedStorage) / float64(totalStorage)

	// 基础 Gas 价格
	baseGasPrice := 10.0

	// 根据存储使用率调整 Gas 价格
	if storageUsageRate > 0.8 {
		baseGasPrice *= 2 // 如果存储使用率超过 80%，则 Gas 价格翻倍
	} else if storageUsageRate < 0.5 {
		baseGasPrice *= 0.8 // 如果存储使用率低于 50%，则 Gas 价格打八折
	}

	// 根据文件大小调整 Gas 价格
	if fileSize > 1<<20 { // 1 MB
		baseGasPrice *= 1.5 // 如果文件大小超过 1 MB，则 Gas 价格增加 50%
	}

	// 根据存储时间调整 Gas 价格
	if storageTime > time.Hour*24*365 { // 1 年
		baseGasPrice *= 2 // 如果存储时间超过 1 年，则 Gas 价格翻倍
	}

	// 根据网络拥堵情况调整 Gas 价格
	baseGasPrice *= (1 + networkCongestion) // 如果网络拥堵，根据拥堵程度增加 Gas 价格

	// 返回动态计算的 Gas 价格
	return big.NewInt(int64(baseGasPrice))
}

func CalculateStorageFee(fileSize int64, storageTime time.Duration, pricePerBytePerSecond *big.Int) *big.Int {
	storageSeconds := new(big.Int).SetInt64(int64(storageTime.Seconds()))
	storageFee := new(big.Int).Mul(big.NewInt(fileSize), storageSeconds)
	return storageFee.Mul(storageFee, pricePerBytePerSecond)
}
