package bpfschain

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	"github.com/snowzach/rotatefilehook"
	"github.com/vrecan/death/v3"
)

// EncodeToBytes 使用 gob 编码将任意数据转换为 []byte
func EncodeToBytes(data interface{}) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)

	err := encoder.Encode(data)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// DecodeFromBytes 使用 gob 解码将 []byte 转换为指定的数据结构
func DecodeFromBytes(data []byte, result interface{}) error {
	buffer := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buffer)

	err := decoder.Decode(result)
	if err != nil {
		return err
	}

	return nil
}

// CloseDB 关闭区块链数据库
// 同步执行：阻塞，直到收到程序强行终止信号关闭数据库，退出程序（一般遇到非常严重的业务逻辑错误时候调用，如检查出现了非法的区块）
// 异步执行：启动协程，如在程序运行过程中遇到程序强行终止信号，关闭数据库，退出程序（本程序有两处调用：StartNode和StartServer）
func CloseDB(chain *Blockchain) {
	//death 管理应用程序的生命终止
	//syscall.SIGINT ctr+c触发
	//syscall.SIGTERM 当前进程被kill(即收到SIGTERM)
	//os.Interrupt 确保在所有系统上的os软件包中存在的两个信号值是os.Interrupt（向进程发送中断）和os.Kill（迫使进程退出）--
	//os.Interrupt 在Windows上，使用os.Process.Signal将os.Interrupt发送到进程的功能没有实现。 它会返回错误而不是发送信号
	d := death.NewDeath(syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	d.WaitForDeathWithFunc(func() {
		defer os.Exit(1)
		defer runtime.Goexit()
		chain.Database.Close()
	})
}

// Flatten 将 [][]byte 转换为 []byte
func Flatten(data [][]byte) []byte {
	var buffer bytes.Buffer
	for _, d := range data {
		length := int32(len(d))
		if err := binary.Write(&buffer, binary.LittleEndian, length); err != nil {
			logrus.Fatalf("Failed to write the length of element: %v", err)
		}
		buffer.Write(d)
	}
	return buffer.Bytes()
}

// Unflatten 将 []byte 还原为 [][]byte
func Unflatten(data []byte) [][]byte {
	buffer := bytes.NewBuffer(data)
	var result [][]byte

	for buffer.Len() > 0 {
		var length int32
		if err := binary.Read(buffer, binary.LittleEndian, &length); err != nil {
			logrus.Fatalf("Failed to read the length of element: %v", err)
		}

		d := make([]byte, length)
		if _, err := buffer.Read(d); err != nil {
			logrus.Fatalf("Failed to read the element: %v", err)
		}
		result = append(result, d)
	}
	return result
}

func ToByte(num int64) []byte {
	buff := new(bytes.Buffer)
	if err := binary.Write(buff, binary.BigEndian, num); err != nil {
		panic(err)
	}

	return buff.Bytes()
}

// ToBytes 泛型函数，用于将不同类型的数据转换为 []byte
func ToBytes[T any](data T) []byte {
	var buf bytes.Buffer

	switch v := any(data).(type) {
	case int:
		// 转换 int 为 int64 以确保一致性
		if err := binary.Write(&buf, binary.LittleEndian, int64(v)); err != nil {
			panic(err)
		}
	default:
		// 对于其他类型，直接写入
		if err := binary.Write(&buf, binary.LittleEndian, data); err != nil {
			panic(err)
		}
	}

	return buf.Bytes()
}

// FromBytes 泛型函数，用于将 []byte 转换回指定类型
func FromBytes[T any](data []byte) T {
	var value T
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &value); err != nil {
		panic(err)
	}
	return value
}

/**

// 时间转换为 []byte
currentTime := time.Now().Unix() // 将时间转换为 Unix 时间戳
currentTimeBytes, _ := toBytes(currentTime)

// []byte 还原为时间
var recoveredTime int64
recoveredTime, _ = fromBytes[int64](currentTimeBytes)
recoveredTimeObject := time.Unix(recoveredTime, 0) // 从 Unix 时间戳还原为 time.Time

// 布尔值转换为 []byte
boolVal := true
boolBytes, _ := toBytes(boolVal)

// []byte 还原为布尔值
var recoveredBool bool
recoveredBool, _ = fromBytes[bool](boolBytes)

// 数字转换为 []byte
num := float64(1234.56)
numBytes, _ := toBytes(num)

// []byte 还原为数字
var recoveredNum float64
recoveredNum, _ = fromBytes[float64](numBytes)

*/

// ReverseBytes 函数将一个字节切片的元素顺序反转。
func ReverseBytes(data []byte) {
	// 使用两个指针i和j从字节切片的两端开始，向中间遍历并交换元素。
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i] // 交换两个元素。
	}
}

const (
	logName = "console"
)

// SetLog 为每一个实例创建一个log文件，记录日志信息
func SetLog(instanceId string) {
	var logLevel = logrus.InfoLevel
	filename := filepath.Join(Logs, fmt.Sprintf("%s.log", logName))
	if instanceId != "" {
		filename = filepath.Join(Logs, fmt.Sprintf("%s_%s.log", logName, instanceId))
	}
	// logrus 的回调钩子
	rotateFileHook, err := rotatefilehook.NewRotateFileHook(rotatefilehook.RotateFileConfig{
		Filename:   filename,
		MaxSize:    50, // 文件最大50M
		MaxBackups: 3,
		MaxAge:     28, // 存储28天
		Level:      logLevel,
		Formatter: &logrus.JSONFormatter{ // 默认为ASCII formatter，转为JSON formatter
			TimestampFormat: "2006-01-02 15:04:05", // 时间戳字符串格式
		},
	})

	if err != nil {
		logrus.Fatalf("初始化文件回调钩子失败: %v", err)
	}

	logrus.SetLevel(logLevel)
	logrus.SetOutput(colorable.NewColorableStdout())
	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC822,
	})
	logrus.AddHook(rotateFileHook)
}

// generateRandomString 生成一个指定长度的随机字符串
func generateRandomString(length int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var result strings.Builder
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		result.WriteByte(letters[num.Int64()])
	}
	return result.String(), nil
}
