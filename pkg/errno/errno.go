package errno

import (
	"errors"
	"fmt"

	base "github.com/Group-lifelong-youth-training/mygomall/rpc_gen/kitex_gen/base"
)

const (
	// System Code
	// 错误码规则 第一位成功0/失败1 第二位服务类型
	SuccessCode    = 0
	ServiceErrCode = 10001
	ParamErrCode   = 10002
	RpcErrCode     = 10003
	// User ErrCode
	LoginErrCode                   = 11001
	UserNotExistErrCode            = 11002
	UserAlreadyExistErrCode        = 11003
	WrongPasswordErrCode           = 11004
	ConfirmPasswordMismatchErrCode = 11005
	// Auth ErrCode
	UnauthorizedDeliverRequestErrCode = 12001
	// Order ErrCode
	UnauthorizedUpdateOrderStatusRequestErrCode = 13001
	// Product ErrCode
	ProductNotExistErrCode           = 14001
	ProductToCategoryNotExistErrCode = 14002
	CategoryNotExistErrCode          = 14003
	CategoryProductEmptyErrCode      = 14004
	ProductStoreNotEnoughErrCode     = 14005
	MessageAlreadyConsumedErrCode    = 14006
	ProductAlreadyExistErrCode       = 14007
)

type ErrNo struct {
	ErrCode int64
	ErrMsg  string
}

func (e ErrNo) Error() string {
	return fmt.Sprintf("err_code=%d, err_msg=%s", e.ErrCode, e.ErrMsg)
}

func NewErrNo(code int64, msg string) ErrNo {
	return ErrNo{code, msg}
}

func (e ErrNo) WithMessage(msg string) ErrNo {
	e.ErrMsg = msg
	return e
}

var (
	Success                                 = NewErrNo(SuccessCode, "Success")
	ServiceErr                              = NewErrNo(ServiceErrCode, "Service is unable to start successfully")
	ParamErr                                = NewErrNo(ParamErrCode, "Wrong Parameter has been given")
	LoginErr                                = NewErrNo(LoginErrCode, "Wrong username or password")
	UserNotExistErr                         = NewErrNo(UserNotExistErrCode, "User does not exists")
	UserAlreadyExistErr                     = NewErrNo(UserAlreadyExistErrCode, "User already exists")
	UnauthorizedDeliverRequestErr           = NewErrNo(UnauthorizedDeliverRequestErrCode, "Unauthorized request")
	RpcErr                                  = NewErrNo(RpcErrCode, "Rpc Err")
	WrongPasswordErr                        = NewErrNo(WrongPasswordErrCode, "Wrong Password")
	ConfirmPasswordMismatchErr              = NewErrNo(ConfirmPasswordMismatchErrCode, "Confirm Password Mismatch")
	UnauthorizedUpdateOrderStatusRequestErr = NewErrNo(UnauthorizedUpdateOrderStatusRequestErrCode, "Changed Order Status Request Not From Checkout")
	ProductNotExistErr                      = NewErrNo(ProductNotExistErrCode, "Product does not exists")
	ProductToCategoryNotExistErr            = NewErrNo(ProductToCategoryNotExistErrCode, "This Product does not exist Categories")
	CategoryNotExistErr                     = NewErrNo(CategoryNotExistErrCode, "Category does not exists")
	CategoryProductEmptyErr                 = NewErrNo(CategoryProductEmptyErrCode, "This Category does have any product")
	ProductStoreNotEnoughErr                = NewErrNo(ProductStoreNotEnoughErrCode, "Product don't have enough store to make order")
	MessageAlreadyConsumedErr               = NewErrNo(MessageAlreadyConsumedErrCode, "This message is already consumed")
	ProductAlreadyExistErr                  = NewErrNo(ProductAlreadyExistErrCode, "This product is already exist ,can't create product")
)

// ConvertErr convert error to Errno
func ConvertErr(err error) ErrNo {
	Err := ErrNo{}
	if errors.As(err, &Err) {
		return Err
	}

	s := ServiceErr
	s.ErrMsg = err.Error()
	return s
}

func HundleRespAndErr(baseresp *base.BaseResp, err error) (handledbaseresp *base.BaseResp) {
	if err != nil {
		handledbaseresp = BuildBaseResp(err)
		return
	}
	if baseresp != nil && baseresp.StatusCode != SuccessCode {
		return baseresp
	}
	handledbaseresp = BuildBaseResp(Success)
	return
}
