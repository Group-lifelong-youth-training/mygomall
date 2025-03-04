// Copyright 2024 CloudWeGo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/Group-lifelong-youth-training/mygomall/pkg/errno"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/utils"
	"gorm.io/gorm"
)

type Product struct {
	Base
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Picture     string  `json:"picture"`
	Price       float32 `json:"price"`
	Store       int32   `json:"store"`
	Status      bool    `json:"status"`
}

func (p Product) TableName() string {
	return "product"
}

func GetProductByID(db *gorm.DB, ctx context.Context, id int64) (product *Product, err error) {
	p := Product{}
	p.Base.ID = id
	err = db.WithContext(ctx).Model(&Product{}).Where(&p).First(&product).Error

	return
}

func CreateProduct(db *gorm.DB, ctx context.Context, product *Product) error {
	_, err := GetProductByID(db, ctx, product.Base.ID)
	log.Println(product.ID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return db.WithContext(ctx).Model(&Product{}).Create(product).Error
		}
		return err
	}
	return errno.ProductAlreadyExistErr
}

func SearchProduct(db *gorm.DB, ctx context.Context, query string) (product []Product, err error) {
	err = db.WithContext(ctx).Model(&Product{}).Where("name REGEXP ?", fmt.Sprintf("^.*%s.*$", query)).Find(&product).Error
	return
}

func ReduceProductStorebyID(db *gorm.DB, ctx context.Context, product_id int64, amount int32) (newStore int32, err error) {

	p, err := GetProductByID(db, ctx, product_id)

	if err != nil {
		return -1, err
	}
	log.Printf("store:%vamount:%v", p.Store, amount)
	newStore = p.Store - amount
	if newStore < 0 {
		err = errno.ProductStoreNotEnoughErr
		return -1, err
	}
	err = db.WithContext(ctx).Model(&Product{}).Where(&Product{Base: Base{ID: product_id}}).Update("store", newStore).Error
	return
}

func (p *Product) BeforeCreate(tx *gorm.DB) (err error) {
	if p.Base.ID == 0 {
		p.Base.ID, _ = utils.GenerateID() // 使用 Snowflake 算法生成 ID
	}

	return
}
