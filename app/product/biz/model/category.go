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

	"github.com/Group-lifelong-youth-training/mygomall/pkg/utils"
	"gorm.io/gorm"
)

type Category struct {
	Base
	Name        string `gorm:"unique" json:"name"`
	Description string `json:"description"`
}

func (c Category) TableName() string {
	return "category"
}

func CreateCategory(db *gorm.DB, ctx context.Context, category *Category) error {
	return db.WithContext(ctx).Create(category).Error
}

func GetCategoryByID(db *gorm.DB, ctx context.Context, id int64) (category *Category, err error) {
	err = db.WithContext(ctx).Model(&Category{}).Where(&Category{Base: Base{ID: id}}).First(&category).Error
	return
}

func GetCategoryByName(db *gorm.DB, ctx context.Context, name string) (category *Category, err error) {
	err = db.WithContext(ctx).Model(&Category{}).Where(&Category{Name: name}).First(&category).Error
	return
}

func (c *Category) BeforeCreate(tx *gorm.DB) (err error) {
	c.Base.ID, _ = utils.GenerateID() // 使用 Snowflake 算法生成 ID
	return
}
