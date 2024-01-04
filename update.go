package bpfschain

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"

	"github.com/inconshreveable/go-update"
	"github.com/sirupsen/logrus"
)

// 自动更新程序
func Selfupdate(data []byte) error {
	reader := bytes.NewReader(data)

	// 使用go-update库应用更新
	if err := update.Apply(reader, update.Options{}); err != nil {
		// 回滚到之前的版本
		if rerr := update.RollbackError(err); rerr != nil {
			logrus.Fatalf("失败回滚到之前版本: %v", rerr)
		}
		return err
	}

	// 重启程序
	return RestartSelf()
}

// func Selfupdate(path string) error {
// 	f, err := os.Open(path)
// 	if err != nil {
// 		logrus.Errorf("Open: %v", err)
// 		return err
// 	}

// 	// 使用go-update库应用更新
// 	if err := update.Apply(f, update.Options{}); err != nil {
// 		// 回滚到之前的版本
// 		if rerr := update.RollbackError(err); rerr != nil {
// 			logrus.Fatalf("失败回滚到之前版本: %v", rerr)
// 		}
// 		return err
// 	}

// 	// 重启程序
// 	return RestartSelf()
// }

// RestartSelf 优雅地关闭当前进程，并启动一个新的进程
func RestartSelf() error {
	// 获取可执行文件的路径
	exe, err := os.Executable()
	if err != nil {
		logrus.Printf("无法获取可执行文件路径: %v", err)
		return err
	}

	// 获取命令行参数
	args := os.Args

	// 获取环境变量
	env := os.Environ()

	// 在Windows上，由于syscall.Exec不可用，需要特殊处理
	if runtime.GOOS == "windows" {
		cmd := exec.Command(exe, args[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Stdin = os.Stdin
		cmd.Env = env

		err := cmd.Start()
		if err != nil {
			logrus.Printf("无法启动新进程: %v", err)
			return err
		}

		// 给一些时间让新进程启动
		time.Sleep(2 * time.Second)

		// 退出当前进程
		os.Exit(0)
	}

	// 在Linux和其他Unix系统上，使用syscall.Exec
	return syscall.Exec(exe, args, env)
}
