package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Group-lifelong-youth-training/mygomall/app/order/biz/model"
	"github.com/cloudwego/kitex/pkg/klog"
	rabbitmq "github.com/wagslane/go-rabbitmq"
)

type LocalMessage struct {
	Topic       string
	MessageBody string
}

var (
	OrderEventPublisher *rabbitmq.Publisher
	conn                *rabbitmq.Conn
	pendingMessages     []LocalMessage
	pendingmessage      LocalMessage
	err                 error
	sourceMsg           model.OrderMessageBody
)

func PublishInit() {
	//TODO 加配置
	conn, err = rabbitmq.NewConn(
		"amqp://root:devops666@localhost:5672/admin_vhost",
		rabbitmq.WithConnectionOptionsLogging,
	)
	if err != nil {
		klog.Fatal(err)
	}

	OrderEventPublisher, err = rabbitmq.NewPublisher(
		conn,
		rabbitmq.WithPublisherOptionsLogging,
		rabbitmq.WithPublisherOptionsExchangeName("order_event_exchange"),
		rabbitmq.WithPublisherOptionsExchangeDeclare,
		rabbitmq.WithPublisherOptionsExchangeKind("topic"),
		rabbitmq.WithPublisherOptionsExchangeDurable,
	)
	if err != nil {
		klog.Fatal(err)
	}
	log.Println("PublishInit seccessful")
}
func PendingMessagesInit() {
	// pendingMessages = []LocalMessage{
	// 	{
	// 		Topic:       "my_routing_key",
	// 		MessageBody: "testpublish1",
	// 	},
	// 	{
	// 		Topic:       "my_routing_key",
	// 		MessageBody: "testpublish2",
	// 	},
	// }
	sourceMsg = model.OrderMessageBody{
		UserId:  100,
		OrderId: 102,
		Items: []model.Product{
			{
				ProductId: 100,
				Quantity:  2,
			},
			{
				ProductId: 200,
				Quantity:  4,
			},
		},
	}
	pendingbyte, err := json.Marshal(sourceMsg)
	if err != nil {
		panic(err)
	}
	pendingmessage.MessageBody = string(pendingbyte)
	pendingmessage.Topic = "order_created_topic"
	pendingMessages = append(pendingMessages, pendingmessage)
	log.Println("PendingMessage seccessful")
}

func main() {
	PublishInit()
	PendingMessagesInit()
	// block main thread - wait for shutdown signal
	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		done <- true
	}()
	ticker := time.NewTicker(time.Second)
	// for {
	// 	select {
	// 	case <-ticker.C:
	// 		for _, msg := range pendingMessages {

	// 			err := OrderEventPublisher.PublishWithContext(
	// 				context.Background(),
	// 				[]byte(msg.MessageBody),
	// 				[]string{msg.Topic},
	// 				// []string{"my_routing_key"},
	// 				rabbitmq.WithPublishOptionsContentType("application/json"),

	// 				rabbitmq.WithPublishOptionsExchange("order_event_exchange"),
	// 			)
	// 			if err != nil {
	// 				return
	// 			}
	// 			log.Printf("message send seccessfully:%v\n", msg.MessageBody)
	// 		}

	// 	case <-done:
	// 		fmt.Println("stopping publisher")
	// 		return
	// 	}

	// }
	select {
	case <-ticker.C:
		for _, msg := range pendingMessages {

			err := OrderEventPublisher.PublishWithContext(
				context.Background(),
				[]byte(msg.MessageBody),
				[]string{msg.Topic},
				rabbitmq.WithPublishOptionsContentType("application/json"),
				rabbitmq.WithPublishOptionsExchange("order_event_exchange"),
			)
			if err != nil {
				return
			}
			log.Printf("message send seccessfully:%v\n", msg.MessageBody)
		}

	case <-done:
		fmt.Println("stopping publisher")
		return
	}

}
