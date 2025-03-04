package service

import (
	"context"

	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
)

type UpdateProductsService struct {
	ctx context.Context
} // NewUpdateProductsService new UpdateProductsService
func NewUpdateProductsService(ctx context.Context) *UpdateProductsService {
	return &UpdateProductsService{ctx: ctx}
}

// Run create note info
func (s *UpdateProductsService) Run(req *product.UpdateProductsReq) (resp *product.UpdateProductsResp, err error) {
	// Finish your business logic.

	return
}
