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

	"gorm.io/gorm"
)

type ProductCategory struct {
	Base
	ProductID  int64 `json:"product_id"`
	CategoryID int64 `json:"category_id"`
}

func (pc ProductCategory) TableName() string {
	return "product_category"
}

func CreateProductCategory(db *gorm.DB, ctx context.Context, pc *ProductCategory) error {

	return db.WithContext(ctx).Create(pc).Error
}

func GetCategoryIDByProductID(db *gorm.DB, ctx context.Context, product_id int64) (category_id []int64, err error) {
	err = db.Model(&ProductCategory{}).Where("product_id = ?", product_id).Select("category_id").Scan(&category_id).Error
	return
}

func GetProductIDByCategoryIDWithLimitOffset(db *gorm.DB, ctx context.Context, category_id int64, limit int64, offset int32) (product_id []int64, err error) {
	err = db.Model(&ProductCategory{}).Where("category_id = ?", category_id).Select("product_id").Scan(&product_id).Error
	return
}
