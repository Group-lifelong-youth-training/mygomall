package rpc

import (
	"sync"

	"github.com/Group-lifelong-youth-training/mygomall/app/product/conf"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/clientsuite"
	"github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/auth/authservice"
	"github.com/cloudwego/kitex/client"
)

var (
	AuthClient   authservice.Client
	once         sync.Once
	err          error
	registryAddr string
	serviceName  string
	commonSuite  client.Option
)

func InitClient() {
	once.Do(func() {
		registryAddr = conf.GetConf().Registry.RegistryAddress[0]
		serviceName = conf.GetConf().Kitex.Service
		commonSuite = client.WithSuite(clientsuite.CommonGrpcClientSuite{
			CurrentServiceName: serviceName,
			RegistryAddr:       registryAddr,
		})

	})
}
