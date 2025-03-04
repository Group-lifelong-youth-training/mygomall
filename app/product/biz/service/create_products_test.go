package service

import (
	"context"
	"testing"
	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
)

func TestCreateProducts_Run(t *testing.T) {
	ctx := context.Background()
	s := NewCreateProductsService(ctx)
	// init req and assert value

	req := &product.CreateProductsReq{}
	resp, err := s.Run(req)
	t.Logf("err: %v", err)
	t.Logf("resp: %v", resp)

	// todo: edit your unit test

}
