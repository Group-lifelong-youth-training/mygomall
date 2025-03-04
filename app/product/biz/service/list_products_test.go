package service

import (
	"context"
	"log"
	"testing"

	"github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal"

	mysql "github.com/Group-lifelong-youth-training/mygomall/app/product/biz/dal/mysql"
	product "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/product"
	"github.com/stretchr/testify/assert"
)

func TestListProducts_Run(t *testing.T) {
	// rpc.InitClient()
	dal.Init()
	if mysql.DB == nil {
		log.Fatalf("DB fail")
		return
	}
	// init req and assert value0

	req := &product.ListProductsReq{CategoryName: "apple", Page: 1, PageSize: 5}
	//测试接口正确性
	t.Run("list_product", func(t *testing.T) {
		resp, err := NewListProductsService(context.Background()).Run(req)
		if err != nil {
			log.Fatalf("err:%v", err)
		}
		t.Logf("err: %v", err)
		t.Logf("resp: %v", resp)
		assert.Equal(t, nil, err)
		assert.Equal(t, "test1", resp.Products[0].Name)
		assert.Equal(t, "test2", resp.Products[1].Name)
	})

	// todo: edit your unit test

}
