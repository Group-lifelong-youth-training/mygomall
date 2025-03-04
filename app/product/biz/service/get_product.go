package service

import (
	"context"
	"errors"

	mysql "github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/mysql"
	model "github.com/Group-lifelong-youth-training/mygomall/app/product/biz/model"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/errno"
	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
	"gorm.io/gorm"
)

type GetProductService struct {
	ctx context.Context
}

// NewGetProductService new GetProductService
func NewGetProductService(ctx context.Context) *GetProductService {
	return &GetProductService{ctx: ctx}
}

// Run create note info
func (s *GetProductService) Run(req *product.GetProductReq) (resp *product.GetProductResp, err error) {
	// Finish your business logic.
	resp = new(product.GetProductResp)
	resp.Product = new(product.Product)
	p := &model.Product{}
	//先查product
	p, err = model.GetProductByID(mysql.DB, s.ctx, req.Id)

	//如果查不到就用返回自定义err表示查不到
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = errno.ProductNotExistErr
		}
		return nil, err
	}
	//如果查到了就填入返回值
	resp.Product.Id = p.ID
	resp.Product.Name = p.Name
	resp.Product.Description = p.Description
	resp.Product.Picture = p.Picture
	resp.Product.Price = p.Price
	resp.Product.Status = p.Status
	resp.Product.Store = p.Store
	//然后再根据商品-类别表查到商品里所属哪些类别
	c_ids, err := model.GetCategoryIDByProductID(mysql.DB, s.ctx, req.Id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = errno.ProductToCategoryNotExistErr
		}
		return resp, err
	}

	for _, c_id := range c_ids {
		c, err := model.GetCategoryByID(mysql.DB, s.ctx, c_id)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				err = errno.CategoryNotExistErr
			}
			continue
		}
		resp.Product.Categories = append(resp.Product.Categories, c.Name)
	}
	return resp, err
}
