package service

import (
	"context"
	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
)

type CreateProductsService struct {
	ctx context.Context
} // NewCreateProductsService new CreateProductsService
func NewCreateProductsService(ctx context.Context) *CreateProductsService {
	return &CreateProductsService{ctx: ctx}
}

// Run create note info
func (s *CreateProductsService) Run(req *product.CreateProductsReq) (resp *product.CreateProductsResp, err error) {
	// Finish your business logic.

	return
}
