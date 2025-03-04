package service

import (
	"context"
	"errors"

	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/mysql"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/model"
	"github.com/Group-lifelong-youth-training/mygomall/pkg/errno"
	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
	"gorm.io/gorm"
)

type SearchProductsService struct {
	ctx context.Context
} // NewSearchProductsService new SearchProductsService
func NewSearchProductsService(ctx context.Context) *SearchProductsService {
	return &SearchProductsService{ctx: ctx}
}

// Run create note info
func (s *SearchProductsService) Run(req *product.SearchProductsReq) (resp *product.SearchProductsResp, err error) {
	// Finish your business logic.
	resp = new(product.SearchProductsResp)
	products, err := model.SearchProduct(mysql.DB, s.ctx, req.Query)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = errno.ProductNotExistErr
		}
		return nil, err
	}
	for _, p := range products {
		resp.Results = append(resp.Results, &product.Product{
			Id:          p.Base.ID,
			Name:        p.Name,
			Description: p.Description,
			Picture:     p.Picture,
			Price:       p.Price,
			Store:       p.Store,
			Status:      p.Status,
		})
	}
	return
}
