package slim

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
)

// Router is interface for routing requests to registered routes.
type Router interface {
	// Add 注册请求处理器，返回对应的路由接口实例
	Add([]string, string, HandlerFunc) (Route, error)
	// Remove 移除路由
	Remove(methods []string, path string) error
	// Routes 返回注册的路由
	Routes() []Route
	// Match 匹配路由
	Match(req *http.Request, params *PathParams) RouteMatch
	MiddlewareRegistrar
	MiddlewareComposer
	RouteRegistrar
}

// RouteCollector 路由收集器接口
type RouteCollector interface {
	// Prefix 返回路由共用前缀
	Prefix() string
	// Parent 返回上级路由收集器
	Parent() RouteCollector
	// Router 返回所属路由器
	Router() Router
	MiddlewareRegistrar
	MiddlewareComposer
	RouteRegistrar
}

type RouteRegistrar interface {
	// Group 实现路由分组注册，实际调用 `RouteCollector.Route` 实现
	Group(fn func(sub RouteCollector))
	// Route 以指定前缀实现路由分组注册
	Route(prefix string, fn func(sub RouteCollector))
	// Some registers a new route for multiple HTTP methods and path with matching
	// handler in the router. Panics on error.
	Some(methods []string, pattern string, h HandlerFunc) Route
	// Any registers a new route for all supported HTTP methods and path with matching
	// handler in the router. Panics on error.
	Any(pattern string, h HandlerFunc) Route
	// CONNECT registers a new CONNECT route for a path with matching handler in
	// the router. Panics on error.
	CONNECT(pattern string, h HandlerFunc) Route
	// DELETE registers a new DELETE route for a path with matching handler in
	// the router. Panics on error.
	DELETE(pattern string, h HandlerFunc) Route
	// GET registers a new GET route for a path with matching handler in
	// the router. Panics on error.
	GET(pattern string, h HandlerFunc) Route
	// HEAD registers a new HEAD route for a path with matching handler in
	// the router. Panics on error.
	HEAD(pattern string, h HandlerFunc) Route
	// OPTIONS registers a new OPTIONS route for a path with matching handler
	// in the router. Panics on error.
	OPTIONS(pattern string, h HandlerFunc) Route
	// PATCH registers a new PATCH route for a path with matching handler in
	// the router. Panics on error.
	PATCH(pattern string, h HandlerFunc) Route
	// POST registers a new POST route for a path with matching handler in
	// the router. Panics on error.
	POST(pattern string, h HandlerFunc) Route
	// PUT registers a new PUT route for a path with matching handler in
	// the router. Panics on error.
	PUT(pattern string, h HandlerFunc) Route
	// TRACE registers a new TRACE route for a path with matching handler in
	// the router. Panics on error.
	TRACE(pattern string, h HandlerFunc) Route
	// Static registers a new route with path prefix to serve static files
	// from the provided root directory. Panics on error.
	Static(prefix, root string) Route
	// File registers a new route with a path to serve a static file.
	// Panics on error.
	File(pattern, file string) Route
}

// Route 路由接口
type Route interface {
	// Router 返回所属路由器
	Router() Router
	// Collector 返回所属收集器
	Collector() RouteCollector
	// Name 返回路由名称
	Name() string
	// SetName 设置路由名称，返回 Route 方便链式操作。
	SetName(name string) Route
	// Pattern 路由路径表达式
	Pattern() string
	// Methods 返回支持的 HTTP 请求方法
	Methods() []string
	// Handler 返回注册的请求处理器函数
	Handler() HandlerFunc
	// Params 返回支持的路由参数列表
	Params() []string
	// ToRouteInfo 返回路由描述接口实例
	ToRouteInfo() RouteInfo
	// Use 注册中间件，返回 Route 方便链式操作。
	Use(middleware ...MiddlewareFunc) Route
	// Middleware 返回注册的中间件
	Middleware() []MiddlewareFunc
	MiddlewareComposer
}

// RouteInfo 路由描述接口
type RouteInfo interface {
	// Router 返回所属路由器
	Router() Router
	// Collector 返回所属收集器
	Collector() RouteCollector
	// Name 返回路由名称
	Name() string
	// Methods 返回支持的请求方法列表
	Methods() []string
	// Pattern 路由路径表达式
	Pattern() string
	// Params 返回支持的路由参数列表
	Params() []string
	// Reverse 通过提供的参数来反转路由表达式，返回为真实请求路径。
	// 如果参数为空或 nil 时则尝试使用用默认值，若无法解决参数
	// 则会 panic 错误
	Reverse(params ...any) string
}

// RouteMatchType describes possible states that request could be in perspective of routing
type RouteMatchType uint8

const (
	// RouteMatchUnknown is state before routing is done. Default state for fresh context.
	RouteMatchUnknown RouteMatchType = iota
	// RouteMatchNotFound is state when router did not find matching route for current request
	RouteMatchNotFound
	// RouteMatchMethodNotAllowed is state when router did not find route with matching path + method for current request.
	// Although router had a matching route with that path but different method.
	RouteMatchMethodNotAllowed
	// RouteMatchFound is state when router found exact match for path + method combination
	RouteMatchFound
)

// RouteMatch is result object for Router.Match. Its main purpose is to avoid allocating memory for PathParams inside router.
type RouteMatch struct {
	// Type contains a result as enumeration of Router.Match and helps to understand did Router actually matched Route or
	// what kind of error case (404/405) we have at the end of the handler chain.
	Type RouteMatchType
	// AllowMethods 能够接受处理的请求方法列表，主要
	// 在 Type 值为 RouteMatchMethodNotAllowed 时被使用。
	AllowMethods []string
	// Handler is function(chain) that was matched by router. In case of no match could result to ErrNotFound or ErrMethodNotAllowed.
	Handler HandlerFunc
	// RouteInfo is information about the route we just matched
	RouteInfo RouteInfo
}

type RouterConfig struct {
	AllowOverwritingRoute    bool
	UnescapePathParamValues  bool
	UseEscapedPathForRouting bool
	RoutingTrailingSlash     bool
	RouteCollector           RouteCollector
	ErrorHandler             ErrorHandlerFunc
}

func NewRouter(config RouterConfig) Router {
	r := &defaultRouter{
		collector:                config.RouteCollector,
		tree:                     &node{},
		routes:                   make([]Route, 0),
		middleware:               make([]MiddlewareFunc, 0),
		errorHandler:             config.ErrorHandler,
		allowOverwritingRoute:    config.AllowOverwritingRoute,
		unescapePathParamValues:  config.UnescapePathParamValues,
		useEscapedPathForRouting: config.UseEscapedPathForRouting,
		routingTrailingSlash:     config.RoutingTrailingSlash,
	}
	if r.collector == nil {
		r.collector = NewRouteCollector("", nil, r)
	}
	return r
}

func NewRouteCollector(prefix string, parent RouteCollector, router Router) RouteCollector {
	if router == nil {
		if parent != nil {
			router = parent.Router()
		}
	} else if parent != nil {
		if parent.Router() != router {
			panic("invalid router for the given parent")
		}
	}
	if router == nil {
		panic("no router")
	}
	return &defaultRouteCollector{
		prefix: prefix,
		parent: parent,
		router: router,
	}
}

var nextRouteId uint32

type defaultRouter struct {
	collector    RouteCollector   // 路由收集器
	tree         *node            // 路由节点树，与根节点的节点树相同
	routes       []Route          // 实际类型是 `[]*defaultRoute`
	middleware   []MiddlewareFunc // 中间件列表
	errorHandler ErrorHandlerFunc // 路由级别的错误处理器
	slim         *Slim

	allowOverwritingRoute    bool
	unescapePathParamValues  bool
	useEscapedPathForRouting bool
	routingTrailingSlash     bool
}

func (r *defaultRouter) Use(middleware ...MiddlewareFunc) {
	r.middleware = append(r.middleware, middleware...)
}

func (r *defaultRouter) Middleware() []MiddlewareFunc {
	return r.middleware
}

func (r *defaultRouter) Compose() MiddlewareFunc {
	return Compose(r.middleware...)
}

func (r *defaultRouter) Add(methods []string, pattern string, h HandlerFunc) (Route, error) {
	segments, trailingSlash := split(pattern)
	params := make([]string, 0)
	tail, _ := r.tree.insert(segments, &params, 0)
	route := &defaultRoute{
		id:        atomic.AddUint32(&nextRouteId, 1),
		collector: r.collector,
		pattern:   strings.Join(segments, ""),
		methods:   methods,
		params:    params,
		handler:   h,
	}
	for _, method := range methods {
		if e := tail.leaf.endpoint(method); e != nil {
			if !r.allowOverwritingRoute {
				panic(errors.New("slim: adding duplicate route (same method+path) is not allowed"))
			}
			r.routes = slices.DeleteFunc(r.routes, func(route Route) bool {
				return route.(*defaultRoute).id == e.routeId
			})
			e.trailingSlash = trailingSlash
			e.routeId = route.id
		} else {
			tail.leaf.endpoints = append(tail.leaf.endpoints, &endpoint{
				method:        method,
				pattern:       route.pattern,
				trailingSlash: trailingSlash,
				routeId:       route.id,
			})
		}
	}
	sort.Sort(tail.leaf.endpoints) // 对端点排序
	r.routes = append(r.routes, route)
	// TODO(hupeh): 如何针对 remove 处理
	if r.slim.contextPathParamAllocSize < tail.leaf.paramsCount {
		r.slim.contextPathParamAllocSize = tail.leaf.paramsCount
	}
	return route, nil
}

func (r *defaultRouter) Group(fn func(sub RouteCollector)) {
	r.collector.Group(fn)
}

func (r *defaultRouter) Route(prefix string, fn func(sub RouteCollector)) {
	r.collector.Route(prefix, fn)
}

func (r *defaultRouter) Some(methods []string, pattern string, h HandlerFunc) Route {
	return r.collector.Some(methods, pattern, h)
}

func (r *defaultRouter) Any(pattern string, h HandlerFunc) Route {
	return r.collector.Any(pattern, h)
}

func (r *defaultRouter) CONNECT(pattern string, h HandlerFunc) Route {
	return r.collector.CONNECT(pattern, h)
}

func (r *defaultRouter) DELETE(pattern string, h HandlerFunc) Route {
	return r.collector.DELETE(pattern, h)
}

func (r *defaultRouter) GET(pattern string, h HandlerFunc) Route {
	return r.collector.GET(pattern, h)
}

func (r *defaultRouter) HEAD(pattern string, h HandlerFunc) Route {
	return r.collector.HEAD(pattern, h)
}

func (r *defaultRouter) OPTIONS(pattern string, h HandlerFunc) Route {
	return r.collector.OPTIONS(pattern, h)
}

func (r *defaultRouter) PATCH(pattern string, h HandlerFunc) Route {
	return r.collector.PATCH(pattern, h)
}

func (r *defaultRouter) POST(pattern string, h HandlerFunc) Route {
	return r.collector.POST(pattern, h)
}

func (r *defaultRouter) PUT(pattern string, h HandlerFunc) Route {
	return r.collector.PUT(pattern, h)
}

func (r *defaultRouter) TRACE(pattern string, h HandlerFunc) Route {
	return r.collector.TRACE(pattern, h)
}

func (r *defaultRouter) Static(prefix, root string) Route {
	return r.collector.Static(prefix, root)
}

func (r *defaultRouter) File(pattern, file string) Route {
	return r.collector.File(pattern, file)
}

// Remove 通过 `method+pattern` 的组合移除服务端点
func (r *defaultRouter) Remove(methods []string, pattern string) error {
	segments, trailingSlash := split(pattern)
	routes, ok := r.tree.remove(methods, trailingSlash, r.routingTrailingSlash, segments, 0)
	if !ok {
		return nil
	}
	for _, route := range routes {
		i := slices.IndexFunc(r.routes, func(x Route) bool {
			return x.(*defaultRoute).id == route
		})
		if i == -1 {
			return errors.New("route not found")
		}
		r.routes[i].(*defaultRoute).Remove()
	}
	return nil
}

func (r *defaultRouter) Routes() []Route {
	return r.routes
}

func (r *defaultRouter) Match(req *http.Request, pathParams *PathParams) RouteMatch {
	*pathParams = (*pathParams)[0:cap(*pathParams)]
	path := req.URL.Path
	if r.useEscapedPathForRouting && req.URL.RawPath != "" {
		path = req.URL.RawPath
	}
	segments, tailingSlash := split(path)
	tail := r.tree.match(segments, 0)
	result := RouteMatch{Type: RouteMatchNotFound, Handler: NotFoundHandler}
	if tail == nil {
		*pathParams = (*pathParams)[0:0]
		return result
	}
	// 安装叶子参数数量重新分配长度
	*pathParams = (*pathParams)[0:tail.leaf.paramsCount]
	var ep *endpoint
	result.AllowMethods, ep = tail.leaf.match(req.Method)
	if ep == nil || (ep.trailingSlash != tailingSlash && !r.routingTrailingSlash) {
		// TODO(hupeh): 在使用 OPTIONS 方法的情况下，可以使用该节点拥有的方法列表进行响应。
		// FIXME: See https://httpwg.org/specs/rfc7231.html#OPTIONS
		result.Type = RouteMatchMethodNotAllowed
		result.Handler = MethodNotAllowedHandler
		return result
	}
	// 查找路由
	var route *defaultRoute
	for _, rr := range r.routes {
		dr := rr.(*defaultRoute)
		if dr.id == ep.routeId {
			route = dr
			break
		}
	}
	// 找不到直接内部错误
	if route == nil {
		panic(fmt.Errorf(
			"slim: route %s@%s#%d not found",
			req.Method, ep.pattern, ep.routeId,
		))
	}
	pattern := route.Pattern()
	var index int
	for i, l := 0, len(pattern); i < l; i++ {
		if pattern[i] == paramLabel || pattern[i] == anyLabel {
			j := i
			for ; j < l && pattern[j] != pathSeparator; j++ {
			}
			i = j
			if index >= tail.leaf.paramsCount {
				panic(fmt.Errorf(
					"slim: invalid param count for routing  %s@%s#%d",
					req.Method, ep.pattern, ep.routeId,
				))
			}
			key := pattern[i+1 : j]
			value := segments[index][1:]
			if pattern[i] == anyLabel {
				if key == "" {
					key = string(anyLabel)
				}
				value = strings.Join(segments[index:], "/")[1:]
				if tailingSlash {
					value += "/"
				}
				i = l
			}
			//  there are cases when path parameter needs to be unescaped
			tmpVal, err := url.PathUnescape(value)
			if err == nil { // handle problems by ignoring them.
				value = tmpVal
			}
			(*pathParams)[index].Name = key
			(*pathParams)[index].Value = value
			index++
		}
	}
	result.Type = RouteMatchFound
	result.Handler = ComposeChainHandler(route)
	result.RouteInfo = route.ToRouteInfo()
	return result
}

// ComposeChainHandler 组合路由收集器的中间件和路由的中间件
func ComposeChainHandler(route Route) HandlerFunc {
	return func(c Context) error {
		stack := make([]MiddlewareFunc, 0)
		collector := route.Collector()
		for collector != nil {
			if mw := collector.Compose(); mw != nil {
				stack = append(stack, mw)
			}
			collector = collector.Parent()
		}
		// 上面是逆向的，所以这里要反转
		slices.Reverse(stack)
		mw := Compose(stack...)
		h := HandlerFunc(func(c Context) error {
			h2 := route.Handler()
			mw2 := Compose(route.Middleware()...)
			if mw2 != nil {
				return mw2(c, h2)
			}
			return h2(c)
		})
		if mw == nil {
			return h(c)
		}
		return mw(c, h)
	}
}

type defaultRouteCollector struct {
	prefix     string           // 路由前缀
	parent     RouteCollector   // 上级路由收集器
	router     Router           // 上级路由器
	middleware []MiddlewareFunc // 中间件列表
}

func (c *defaultRouteCollector) Prefix() string {
	return c.prefix
}

func (c *defaultRouteCollector) Parent() RouteCollector {
	return c.parent
}

func (c *defaultRouteCollector) Router() Router {
	return c.router
}

func (c *defaultRouteCollector) Use(middleware ...MiddlewareFunc) {
	c.middleware = append(c.middleware, middleware...)
}

func (c *defaultRouteCollector) Middleware() []MiddlewareFunc {
	return c.middleware
}

func (c *defaultRouteCollector) Compose() MiddlewareFunc {
	return Compose(c.middleware...)
}

func (c *defaultRouteCollector) Group(fn func(sub RouteCollector)) {
	if fn != nil {
		fn(NewRouteCollector("", c, nil))
	}
}

func (c *defaultRouteCollector) Route(prefix string, fn func(sub RouteCollector)) {
	if fn != nil {
		fn(NewRouteCollector(prefix, c, nil))
	}
}

func (c *defaultRouteCollector) Some(methods []string, pattern string, h HandlerFunc) Route {
	var collector RouteCollector
	collector = c
	for collector != nil {
		pattern = collector.Prefix() + pattern
		collector = collector.Parent()
	}
	route, err := c.Router().Add(methods, pattern, h)
	if err != nil {
		panic(err)
	}
	return route
}

func (c *defaultRouteCollector) Any(pattern string, h HandlerFunc) Route {
	return c.Some([]string{"*"}, pattern, h)
}

func (c *defaultRouteCollector) method(method string, pattern string, h HandlerFunc) Route {
	return c.Some([]string{method}, pattern, h)
}

func (c *defaultRouteCollector) CONNECT(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodConnect, pattern, h)
}

func (c *defaultRouteCollector) DELETE(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodDelete, pattern, h)
}

func (c *defaultRouteCollector) GET(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodGet, pattern, h)
}

func (c *defaultRouteCollector) HEAD(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodHead, pattern, h)
}

func (c *defaultRouteCollector) OPTIONS(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodOptions, pattern, h)
}

func (c *defaultRouteCollector) PATCH(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodPatch, pattern, h)
}

func (c *defaultRouteCollector) POST(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodPost, pattern, h)
}

func (c *defaultRouteCollector) PUT(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodPut, pattern, h)
}

func (c *defaultRouteCollector) TRACE(pattern string, h HandlerFunc) Route {
	return c.method(http.MethodTrace, pattern, h)
}

func (c *defaultRouteCollector) Static(prefix, root string) Route {
	return c.GET(prefix+"*", StaticDirectoryHandler(root, false))
}

func (c *defaultRouteCollector) File(pattern, file string) Route {
	return c.GET(pattern, func(c Context) error { return c.File(file) })
}

// StaticDirectoryHandler creates handler function to serve files from given a root path
func StaticDirectoryHandler(root string, disablePathUnescaping bool) HandlerFunc {
	if root == "" {
		root = "." // For security, we want to restrict to CWD.
	}
	return func(c Context) error {
		p := c.PathParam("*")
		if !disablePathUnescaping { // when router is already unescaping, we do not want to do is twice
			tmpPath, err := url.PathUnescape(p)
			if err != nil {
				return fmt.Errorf("failed to unescape path variable: %w", err)
			}
			p = tmpPath
		}

		name := filepath.Join(root, filepath.Clean("/"+p)) // "/"+ for security
		fi, err := fs.Stat(c.Filesystem(), name)
		if err != nil {
			// The access path does not exist
			return ErrNotFound
		}

		// If the request is for a directory and does not end with "/"
		p = c.Request().URL.Path // the path must not be empty.
		if fi.IsDir() && p[len(p)-1] != '/' {
			// Redirect to end with "/"
			return c.Redirect(http.StatusMovedPermanently, p+"/")
		}
		return c.File(name)
	}
}

type defaultRoute struct {
	id         uint32
	name       string
	collector  RouteCollector
	pattern    string
	methods    []string
	params     []string
	handler    HandlerFunc
	middleware []MiddlewareFunc
}

func (r *defaultRoute) SetName(name string) Route {
	r.name = name
	return r
}
func (r *defaultRoute) Use(middleware ...MiddlewareFunc) Route {
	r.middleware = append(r.middleware, middleware...)
	return r
}
func (r *defaultRoute) ID() uint32                   { return r.id }
func (r *defaultRoute) Router() Router               { return r.collector.Router() }
func (r *defaultRoute) Collector() RouteCollector    { return r.collector }
func (r *defaultRoute) Name() string                 { return r.name }
func (r *defaultRoute) Pattern() string              { return r.pattern }
func (r *defaultRoute) Methods() []string            { return r.methods[:] }
func (r *defaultRoute) Handler() HandlerFunc         { return r.handler }
func (r *defaultRoute) Params() []string             { return r.params[:] }
func (r *defaultRoute) Middleware() []MiddlewareFunc { return r.middleware[:] }
func (r *defaultRoute) Compose() MiddlewareFunc      { return Compose(r.middleware...) }
func (r *defaultRoute) ToRouteInfo() RouteInfo       { return r }
func (r *defaultRoute) Remove() {
	router := r.Router()
	if x, ok := router.(*defaultRouter); ok {
		x.routes = slices.DeleteFunc(x.routes, func(route Route) bool {
			return route.(*defaultRoute).id == r.id
		})
	} else {
		// 为自定义路由器提供移除子路由的预留接口
		if i, yes := router.(interface{ RemoveRoute(Route) }); yes {
			i.RemoveRoute(r)
		}
	}
}
func (r *defaultRoute) Reverse(params ...any) string {
	uri := new(bytes.Buffer)
	ln := len(params)
	n := 0
	for i, l := 0, len(r.pattern); i < l; i++ {
		if (r.pattern[i] == paramLabel || r.pattern[i] == anyLabel) && n < ln {
			for ; i < l && r.pattern[i] != pathSeparator; i++ {
			}
			if n < ln {
				uri.WriteString(fmt.Sprintf("%v", params[n]))
			}
			n++
		}
		if i < l {
			uri.WriteByte(r.pattern[i])
		}
	}
	return uri.String()
}
