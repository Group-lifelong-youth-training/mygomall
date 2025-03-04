package dal

import (
	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/mysql"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/redis"
)

func Init() {
	redis.Init()
	mysql.Init()
}

func Shutdown() {
	sqlDB, _ := mysql.DB.DB()
	sqlDB.Close()
	redis.RedisClient.Close()
}
