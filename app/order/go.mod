module github.com/Group-lifelong-youth-training/mygomall/app/order

go 1.23.5

replace github.com/apache/thrift => github.com/apache/thrift v0.13.0

require gorm.io/plugin/soft_delete v1.2.1

require github.com/rabbitmq/amqp091-go v1.10.0 // indirect

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.4 // indirect
	github.com/wagslane/go-rabbitmq v0.15.0
	gorm.io/gorm v1.23.0 // indirect
)
