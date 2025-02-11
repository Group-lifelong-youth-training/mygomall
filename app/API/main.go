package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Group-lifelong-youth-training/mygomall/app/API/rpc"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/HTTPviper"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/jwt"
	etcd "github.com/Group-lifelong-youth-training/mygomall/pkg/registry-etcd"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/app/server/registry"
	"github.com/cloudwego/hertz/pkg/common/config"
	"github.com/cloudwego/hertz/pkg/common/hlog"
	"github.com/cloudwego/hertz/pkg/network/netpoll"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/kitex/pkg/utils"
	"github.com/hertz-contrib/gzip"
	h2config "github.com/hertz-contrib/http2/config"
	"github.com/hertz-contrib/http2/factory"
	hertztracing "github.com/hertz-contrib/obs-opentelemetry/tracing"
	"github.com/hertz-contrib/pprof"
	"github.com/hertz-contrib/registry/etcd"
	"github.com/kitex-contrib/obs-opentelemetry/provider"
	"time"
)

//使用hertz提供api，然后转发http请求给rpc

// 使用tls加密和进行身份验证
type TLs struct {
	Enable bool `json:"Enable" yaml:"Enable"`
	Config tls.Config
	Cert   string `json:"CertFile" yaml:"CertFile"`
	Key    string `json:"KeyFile" yaml:"KeyFile"`
	ALPN   bool   `json:"ALPN" yaml:"ALPN"`
}

type Http2 struct {
	Enable bool `json:"Enable" yaml:"Enable"`
	//禁用长连接
	DisableKeepalive bool     `json:"DisableKeepalive" yaml:"DisableKeepalive"`
	ReadTimeout      Duration `json:"ReadTimeout" yaml:"ReadTimeout"`
}

type HertzConfig struct {
	UseNetpoll bool  `json:"useNetpoll" yaml:"useNetpoll"`
	Http2      Http2 `json:"http2" yaml:"http2"`
	Tls        TLs   `json:"tls" yaml:"tls"`
}

// 用于处理 JSON 序列化和反序列化。
type Duration struct {
	time.Duration
}

var (
	//初始化viper
	Config = HTTPviper.ConfigInit("MyGoMallAPI", "APIConfig")
	//config的各种需要用到的参数
	ServiceName = Config.Viper.GetString("MyGoMallService")
	ServiceAddr = fmt.Sprintf("%s:%d",
		Config.Viper.GetString("MyGoMallService.addr"),
		Config.Viper.GetInt("MyGoMall.Port"))
	EtcdAddress = fmt.Sprintf("%s:%d",
		Config.Viper.GetString("Etcd.Address"),
		Config.Viper.GetInt("Etcd.Port"))

	Jwt         *jwt.JWT
	hertzConfig HertzConfig //hertz配置信息
)

// 序列化处理
func (d Duration) MarshalJSON() (data []byte, err error) { return json.Marshal(d.String()) }

// 反序列化的处理
func (d *Duration) UnMarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case string:
		var err error
		d.Duration, err = time.ParseDuration(value)
		if err != nil {
			return err
		}
		return nil

	case float64:
		d.Duration = time.Duration(value)
		return nil

	default:
		return errors.New("invalid duration")
	}
}

//初始化api
func Init() {
	rpc.InitRPC(&Config)
	//初始化jwt
	Jwt = jwt.NewJWT([]byte(Config.Viper.GetString("JWT.signingKey")))
}

// 初始化hertz配置
func InitHertzConfig() {
	hertzV, err := json.Marshal(Config.Viper.Sub("Hertz").AllSettings())
	if err != nil {
		hlog.Fatalf("Error marshalling hertz config!%s", err)
	}
	if err = json.Unmarshal(hertzV, &hertzConfig); err != nil {
		hlog.Fatalf("Error unmarshalling hertz config!%s", err)
	}
}

// 初始化hertz
func InitHertz() *server.Hertz {
	InitHertzConfig()

	opts := []config.Option{}

	//服务注册
	if Config.Viper.GetBool("Etcd.Enable") {
		r, err := etcd.NewEtcdRegistry([]string{EtcdAddress})
		if err != nil {
			hlog.Fatal(err)
		}

		opts = append(opts, server.WithRegistry(r, registry.Info{
			ServiceName: ServiceName,
			Addr:        utils.NewNetAddr("tcp", ServiceAddr),
			Weight:      10,
			Tags:        nil,
		}))
	}

	// 链路追踪
	p := provider.NewOpenTelemetryProvider(
		provider.WithServiceName(ServiceName),
		provider.WithExportEndpoint("localhost:4317"),
		provider.WithInsecure(),
	)
	defer p.Shutdown(context.Background())
	tracer, tracerCfg := hertztracing.NewServerTracer()
	opts = append(opts, tracer)

	// 网络库
	hertzNet := standard.NewTransporter
	if hertzConfig.UseNetpoll {
		hertzNet = netpoll.NewTransporter
	}
	opts = append(opts, server.WithTransport(hertzNet))

	// TLS & Http2
	tlsEnable := hertzConfig.Tls.Enable
	h2Enable := hertzConfig.Http2.Enable
	hertzConfig.Tls.Config = tls.Config{
		MinVersion:       tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
	if tlsEnable {
		cert, err := tls.LoadX509KeyPair(hertzConfig.Tls.Cert, hertzConfig.Tls.Key)
		if err != nil {
			hlog.Error(err)
		}
		hertzConfig.Tls.Config.Certificates = append(hertzConfig.Tls.Config.Certificates, cert)
		opts = append(opts, server.WithTLS(&hertzConfig.Tls.Config))

		if alpn := hertzConfig.Tls.ALPN; alpn {
			opts = append(opts, server.WithALPN(alpn))
		}
	} else if h2Enable {
		opts = append(opts, server.WithH2C(h2Enable))
	}

	// Hertz
	h := server.Default(opts...)
	h.Use(gzip.Gzip(gzip.DefaultCompression),
		hertztracing.ServerMiddleware(tracerCfg))

	// Protocol
	if h2Enable {
		h.AddProtocol("h2", factory.NewServerFactory(
			h2config.WithReadTimeout(hertzConfig.Http2.ReadTimeout.Duration),
			h2config.WithDisableKeepAlive(hertzConfig.Http2.DisableKeepalive)))
		if tlsEnable {
			hertzConfig.Tls.Config.NextProtos = append(hertzConfig.Tls.Config.NextProtos, "h2")
		}
	}

	return h
}
