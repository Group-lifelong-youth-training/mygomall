package service

import (
	"context"
	"errors"
	"log"

	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/mysql"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/model"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/errno"
	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
	"gorm.io/gorm"
)

type ListProductsService struct {
	ctx context.Context
} // NewListProductsService new ListProductsService
func NewListProductsService(ctx context.Context) *ListProductsService {
	return &ListProductsService{ctx: ctx}
}

// Run create note info
func (s *ListProductsService) Run(req *product.ListProductsReq) (resp *product.ListProductsResp, err error) {
	// Finish your business logic.
	resp = new(product.ListProductsResp)

	category, err := model.GetCategoryByName(mysql.DB, s.ctx, req.CategoryName)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = errno.CategoryNotExistErr
		}
		return nil, err
	}
	//page从1开始，offset从0开始，所以如下page-1计算
	product_ids, err := model.GetProductIDByCategoryIDWithLimitOffset(mysql.DB, s.ctx, category.ID, req.PageSize, (req.Page-1)*int32(req.PageSize))
	log.Printf("%#v", product_ids)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = errno.CategoryProductEmptyErr
		}
		return nil, err
	}

	for _, product_id := range product_ids {
		p, err := model.GetProductByID(mysql.DB, s.ctx, product_id)
		if err != nil {
			continue
		}
		allCategoriesID, err := model.GetCategoryIDByProductID(mysql.DB, s.ctx, product_id)
		if err != nil {
			return nil, err
		}
		allCategories := make([]string, 0)
		for oneCategoryID := range allCategoriesID {
			oneCategory, err := model.GetCategoryByID(mysql.DB, s.ctx, int64(oneCategoryID))
			if err != nil {
				continue
			}
			allCategories = append(allCategories, oneCategory.Name)
		}

		pro := new(product.Product)
		pro.Id = p.ID
		pro.Name = p.Name
		pro.Description = p.Description
		pro.Price = p.Price
		pro.Store = p.Store
		pro.Picture = p.Picture
		pro.Categories = allCategories
		resp.Products = append(resp.Products, pro)
	}
	return
}
