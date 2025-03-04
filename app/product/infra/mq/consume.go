package mq

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/mysql"
	redisclient "github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/redis"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/model"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/errno"
	redis "github.com/redis/go-redis/v9"

	"github.com/cloudwego/kitex/pkg/klog"
	"github.com/wagslane/go-rabbitmq"
)

// 如果没重复消费则去redis标记为已消费
func setConsumptionStatus(ctx context.Context, rdb *redis.Client, userID string, orderID string, consumed int) (err error) {
	//拼接一下key【userID:orderID】
	key := fmt.Sprintf("%s:%s", userID, orderID)
	//去redis找看看能不能找到
	var val string
	val, err = rdb.Get(ctx, key).Result()
	// log.Printf("val:%v,err:%v\n", val, err)
	// 如果取值出错
	if err != nil {
		//如果是因为不存在键
		if err == redis.Nil {
			//则设置值
			seterr := rdb.Set(ctx, key, consumed, 24*time.Hour).Err() // 24小时过期
			//如果设置值失败了
			if seterr != nil {
				klog.Fatal(seterr)
				return seterr
			}
			//设置成功则返回
			return err
		}
		//其他错误直接返回
		return err
	}
	//如果取到了值
	valint, err := strconv.Atoi(val)
	if err != nil {
		klog.Fatal(err)
		return err
	}
	// 如果设置和取到的一样则说明消费过了，报个重复消费的错
	if valint == consumed {
		err = errno.MessageAlreadyConsumedErr
		return err
	}

	return
}

func processMessage(ctx context.Context, msgbyte []byte) {
	// 完成之后往redis存一个userid:orderid 的值为1表示消费过了
	msg := &model.Message{}

	// 对收到的消息反序列化到结构体
	err = json.Unmarshal(msgbyte, msg)
	if err != nil {
		klog.Fatal("unmarshal fault! err:%v", err)
		log.Printf("unmarshal fault! err:%v", err)
		panic(err)
	}
	log.Printf("message struct:%v\n", msg)
	//对是否重复消费进行判断
	err := setConsumptionStatus(ctx, redisclient.RedisClient, strconv.FormatInt(msg.UserId, 10), strconv.FormatInt(msg.OrderId, 10), 1)
	log.Printf("setConsumptionStatus Error:%v\n", err)
	if err != nil {
		//如果没有找到已消费的记录
		if err == redis.Nil {
			//则开始反序列化结构体然后扣库存
			// 取出结构体中的所有商品对其进行库存减少
			var (
				reduceErr error
			)
			for _, item := range msg.Items {
				_, reduceErr = model.ReduceProductStorebyID(mysql.DB, ctx, item.ProductId, item.Quantity)
				if reduceErr != nil {
					if reduceErr == errno.ProductStoreNotEnoughErr {
						log.Println(reduceErr)
					}

					continue
				}
			}
			if reduceErr == nil {
				log.Println("Product reduce store successfully!")
			}

			//如果库存已经扣过，则直接return不扣
		} else if err == errno.MessageAlreadyConsumedErr {

			log.Println(err)
			return
		} else {
			// 其他错误则直接panic
			panic(fmt.Errorf("OtherUnknownError:%v", err))
		}
	}

}

// 消费消息
func Consume() {
	ctx := context.Background()
	err := ProductEventConsumer.Run(func(d rabbitmq.Delivery) rabbitmq.Action {

		log.Printf("consumed: %v", string(d.Body))
		processMessage(ctx, d.Body)
		// rabbitmq.Ack, rabbitmq.NackDiscard, rabbitmq.NackRequeue
		return rabbitmq.Ack
	})
	if err != nil {
		klog.Fatal("consumer fault! err:%v", err)
		return
	}

}
