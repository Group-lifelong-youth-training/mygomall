//基于配置信息初始化客户端，当前只有user服务

package rpc

import "github.com/Group-lifelong-youth-training/mygomall/pkg/HTTPviper"

// InitRPC init rpc client
func InitRPC(Config *HTTPviper.Config) {
	UserConfig := HTTPviper.ConfigInit("TIKTOK_USER", "userConfig")
	initUserRpc(&UserConfig)
}
