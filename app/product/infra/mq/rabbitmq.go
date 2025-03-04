package mq

import (
	"log"

	"github.com/cloudwego/kitex/pkg/klog"
	"github.com/wagslane/go-rabbitmq"
)

var (
	ProductEventConsumer *rabbitmq.Consumer
	conn                 *rabbitmq.Conn

	err error
)

func Init() {

	//TODO 加配置
	conn, err = rabbitmq.NewConn(
		"amqp://root:devops666@localhost:5672/admin_vhost",
		rabbitmq.WithConnectionOptionsLogging,
	)
	if err != nil {
		klog.Fatal(err)
	}

	ProductEventConsumer, err = rabbitmq.NewConsumer(
		conn,
		"my_queue",
		rabbitmq.WithConsumerOptionsLogging,
		rabbitmq.WithConsumerOptionsRoutingKey("order_created_topic"),
		rabbitmq.WithConsumerOptionsExchangeName("order_event_exchange"),
		rabbitmq.WithConsumerOptionsExchangeDeclare,
		rabbitmq.WithConsumerOptionsExchangeKind("topic"),
		rabbitmq.WithConsumerOptionsExchangeDurable,
	)
	if err != nil {
		klog.Fatal(err)
	}
	log.Println("mq init success")
}

// TODO main里要加上关闭mq连接
func Shutdown() {
	conn.Close()
	ProductEventConsumer.Close()
}
