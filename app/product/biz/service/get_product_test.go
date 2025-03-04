package service

import (
	"context"
	"testing"

	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal"
	"github.com/Group-lifelong-youth-training/mygomall/app/product/infra/rpc"
	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
	"github.com/stretchr/testify/assert"
)

func TestGetProduct_Run(t *testing.T) {
	rpc.InitClient()
	dal.Init()

	// init req and assert value0

	req := &product.GetProductReq{Id: 1896515295200153600}

	t.Run("get_product", func(t *testing.T) {
		resp, err := NewGetProductService(context.Background()).Run(req)
		t.Logf("err: %v", err)
		t.Logf("resp: %v", resp)
		assert.Equal(t, "test1", resp.Product.Name)
	})

	// todo: edit your unit test

}
