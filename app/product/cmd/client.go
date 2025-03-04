// Copyright 2024 CloudWeGo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"context"
	"log"

	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/mysql"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/model"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/infra/mq"
	"gorm.io/gorm"
)

// 插入几条数据测试
var (
	db  *gorm.DB
	ctx context.Context
)

func insertData() {

	ctx := context.Background()

	ps := []model.Product{
		{
			Base:        model.Base{ID: 100}, // 如果不需要手动设置 ID，可以去掉
			Name:        "test1",
			Description: "456",
			Store:       10,
			Price:       33.0,
			Picture:     "665",
			Status:      true,
		},
		{
			Base:        model.Base{ID: 200}, // 同上
			Name:        "test2",
			Description: "457",
			Store:       20,
			Price:       34.0,
			Picture:     "666",
			Status:      true,
		},
	}
	log.Printf("ps:%v\n", ps)

	// 插入产品
	for _, p := range ps {

		if err := model.CreateProduct(mysql.DB, ctx, &p); err != nil {
			log.Printf("Error creating product %s: %v", p.Name, err)
		}
	}
}

func main() {
	dal.Init()
	ctx = context.Background()
	insertData()

	mq.Init()
	mq.Consume()

	defer dal.Shutdown()
	defer mq.Shutdown()

}
