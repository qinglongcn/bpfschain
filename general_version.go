package bpfschain

import (
	"context"

	"github.com/bpfs/dep2p/streams"

	"github.com/bpfs/dep2p/pubsub"

	"github.com/bpfs/dep2p"

	"github.com/sirupsen/logrus"
)

type versionPayload struct {
	Version string
	Files   []byte
}

// SendVersion 向指定的 peer 发送版本文件
func SendVersion(p2p *dep2p.DeP2P, bps *pubsub.DeP2PPubSub, peerId string, goos, goarch, version string) error {
	// fs := afero.NewOsFs()

	// 构建文件路径
	// var versionFilePath string
	// if goarch != "" {
	// 	versionFilePath = filepath.Join(Versions, goos, goarch, version)
	// } else {
	// 	versionFilePath = filepath.Join(Versions, goos, version)
	// }

	// 检查文件是否存在
	// if _, err := fs.Stat(versionFilePath); err != nil {
	// 	if os.IsNotExist(err) {
	// 		// 文件不存在
	// 		return nil
	// 	}
	// 	// 其他错误
	// 	return err
	// }

	// 打开文件
	// f, err := fs.Open(versionFilePath)
	// if err != nil {
	// 	return err
	// }
	// defer f.Close()

	// 读取文件内容
	// fileBytes, err := io.ReadAll(f)
	// if err != nil {
	// 	return err
	// }

	payload := versionPayload{
		Version: version,
		// Files:   fileBytes, // 使用文件内容
	}

	// 编码
	payloadBytes, err := EncodeToBytes(payload)
	if err != nil {
		logrus.Errorf("[SendVersion] 编码失败:\t%v", err)
		return err
	}

	// 请求消息
	srm := &streams.RequestMessage{
		Payload: payloadBytes,
		Message: &streams.Message{
			Sender:   p2p.Host().ID().String(), // 发送方ID
			Receiver: peerId,                   // 接收方ID
		},
	}

	// 序列化
	requestBytes, err := srm.Marshal()
	if err != nil {
		logrus.Errorf("[SendVersion] 序列化失败:\t%v", err)
		return err
	}

	// 发送最新版本文件
	if err := bps.BroadcastWithTopic(PubsubBlockchainGeneralVersionChannel, requestBytes); err != nil {
		logrus.Errorf("[SendVersion] 发送失败:\t%v", err)
		return err
	}

	logrus.Printf("[SendVersion]-------- 开始-------- ")
	logrus.Printf("消息类型:\n%+v", srm.Message.Type)
	logrus.Printf("发送方ID:\n%+v", srm.Message.Sender)
	logrus.Printf("接收方ID:\n%+v", srm.Message.Receiver)
	logrus.Printf("发送内容:\n%+v", payload)
	logrus.Printf("[SendVersion]-------- 结束-------- \n\n")

	return nil
}

// HandleVersion 处理接收到的版本文件(所有节点)
func HandleVersion(ctx context.Context, opt *Options, p2p *dep2p.DeP2P, pubsub *pubsub.DeP2PPubSub, chain *Blockchain, pool *MemoryPool, request *streams.RequestMessage) {
	logrus.Printf("[HandleVersion]-------- 开始-------- ")
	logrus.Printf("%+v", request)
	logrus.Printf("[HandleVersion]-------- 结束-------- \n\n")

	payload := new(versionPayload)
	if err := DecodeFromBytes(request.Payload, &payload); err != nil {
		logrus.Errorf("[HandleVersion] 解码失败:\t%v", err)
		return
	}

	// result := CompareVersions(opt.LocalVersion, payload.Version)
	// switch result {
	// case 1:
	// // 本地版本小于对方版本
	// case -1:
	// 	// 自动更新程序
	// 	Selfupdate(payload.Files)
	// case 0:
	// }

}
