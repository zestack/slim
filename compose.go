package slim

import (
	"errors"
	"sync/atomic"
)

// Explicitly 一个承上启下的中间件
func Explicitly(c Context, next HandlerFunc) error {
	return next(c)
}

// Compose 合并多个中间件为一个，实现洋葱模型，
// 有别于 gin/chi/echo 等框架的的后入先出模式。
func Compose(middleware ...MiddlewareFunc) MiddlewareFunc {
	l := len(middleware)
	if l == 0 {
		return nil
	}
	if l == 1 {
		return middleware[0]
	}
	var index int32 = -1
	return func(c Context, next HandlerFunc) error {
		var dispatch func(int) error
		// TODO(hupeh): 测试性能
		dispatch = func(i int) error {
			if int32(i) <= atomic.LoadInt32(&index) {
				return errors.New("next() called multiple times")
			}
			atomic.StoreInt32(&index, int32(i))
			if i == len(middleware) {
				return next(c)
			}
			return middleware[i](c, func(c Context) error {
				return dispatch(i + 1)
			})
		}
		return dispatch(0)
	}
}
