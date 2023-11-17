package slim

import (
	stdctx "context"
	"crypto/tls"
	"errors"
	"io"
	"io/fs"
	stdLog "log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"zestack.dev/color"
	"zestack.dev/log"
)

// MIME types
const (
	MIMEApplicationJSON                  = "application/json"
	MIMEApplicationJSONCharsetUTF8       = "application/json; charset=UTF-8"
	MIMEApplicationJavaScript            = "application/javascript"
	MIMEApplicationJavaScriptCharsetUTF8 = "application/javascript; charset=UTF-8"
	MIMEApplicationXML                   = "application/xml"
	MIMEApplicationXMLCharsetUTF8        = "application/xml; charset=UTF-8"
	MIMETextXML                          = "text/xml"
	MIMETextXMLCharsetUTF8               = "text/xml; charset=UTF-8"
	MIMEApplicationForm                  = "application/x-www-form-urlencoded"
	MIMEApplicationProtobuf              = "application/protobuf"
	MIMEApplicationMsgpack               = "application/msgpack"
	MIMETextHTML                         = "text/html"
	MIMETextHTMLCharsetUTF8              = "text/html; charset=UTF-8"
	MIMETextPlain                        = "text/plain"
	MIMETextPlainCharsetUTF8             = "text/plain; charset=UTF-8"
	MIMEMultipartForm                    = "multipart/form-data"
	MIMEOctetStream                      = "application/octet-stream"
)

// Headers
const (
	HeaderAccept         = "Accept"
	HeaderAcceptEncoding = "Accept-Encoding"
	// HeaderAllow is the name of the "Allow" header field used to list the set of methods
	// advertised as supported by the target resource. Returning an Allow header is mandatory
	// for status 405 (method not found) and useful for the OPTIONS method in responses.
	// See RFC 7231: https://datatracker.ietf.org/doc/html/rfc7231#section-7.4.1
	HeaderAllow               = "Allow"
	HeaderAuthorization       = "Authorization"
	HeaderContentDisposition  = "Content-Disposition"
	HeaderContentEncoding     = "Content-Encoding"
	HeaderContentLength       = "Content-Length"
	HeaderContentType         = "Content-Type"
	HeaderCookie              = "Cookie"
	HeaderSetCookie           = "Set-Cookie"
	HeaderIfModifiedSince     = "If-Modified-Since"
	HeaderLastModified        = "Last-Modified"
	HeaderLocation            = "Location"
	HeaderUpgrade             = "Upgrade"
	HeaderVary                = "Vary"
	HeaderWWWAuthenticate     = "WWW-Authenticate"
	HeaderXForwardedFor       = "X-Forwarded-For"
	HeaderXForwardedProto     = "X-Forwarded-Proto"
	HeaderXForwardedProtocol  = "X-Forwarded-Protocol"
	HeaderXForwardedSsl       = "X-Forwarded-Ssl"
	HeaderXUrlScheme          = "X-Url-Scheme"
	HeaderXHTTPMethodOverride = "X-HTTP-Method-Override"
	HeaderXRealIP             = "X-Real-IP"
	HeaderXRequestID          = "X-Request-ID"
	HeaderXRequestedWith      = "X-Requested-With"
	HeaderServer              = "Server"
	HeaderOrigin              = "Origin"
	HeaderCacheControl        = "Cache-Control"
	HeaderConnection          = "Connection"

	HeaderAccessControlRequestMethod    = "Access-Control-Request-Method"
	HeaderAccessControlRequestHeaders   = "Access-Control-Request-Headers"
	HeaderAccessControlAllowOrigin      = "Access-Control-Allow-Origin"
	HeaderAccessControlAllowMethods     = "Access-Control-Allow-Methods"
	HeaderAccessControlAllowHeaders     = "Access-Control-Allow-Headers"
	HeaderAccessControlAllowCredentials = "Access-Control-Allow-Credentials"
	HeaderAccessControlExposeHeaders    = "Access-Control-Expose-Headers"
	HeaderAccessControlMaxAge           = "Access-Control-Max-Age"

	HeaderStrictTransportSecurity         = "Strict-Transport-Security"
	HeaderXContentTypeOptions             = "X-Content-Type-Config"
	HeaderXXSSProtection                  = "X-XSS-Protection"
	HeaderXFrameOptions                   = "X-Frame-Config"
	HeaderContentSecurityPolicy           = "Content-Security-Policy"
	HeaderContentSecurityPolicyReportOnly = "Content-Security-Policy-Report-Only"
	HeaderXCSRFToken                      = "X-CSRF-Token"
	HeaderReferrerPolicy                  = "Referrer-Policy"
)

const (
	// Version of Server
	Version = "0.0.1-dev"
	website = "https://slim.zestack.com"
	// http://patorjk.com/software/taag/#p=display&f=Small%20Slant&t=Echo
	banner = `
 .--,       .--,
( (  \.---./  ) )
 '.__/o   o\__.'
    {=  ^  =}
     >  -  <
_____________________________________________
High performance, minimalist Go web framework
version: %s
website: %s
_____________________________________________
`
)

// HandlerFunc HTTP请求处理函数签名
type HandlerFunc func(c Context) error

// ErrorHandlerFunc 错误处理函数签名
type ErrorHandlerFunc func(c Context, err error)

// MiddlewareFunc 请求中间件
type MiddlewareFunc func(c Context, next HandlerFunc) error

// MiddlewareRegistrar 中间件注册接口
type MiddlewareRegistrar interface {
	// Use 注册中间件
	Use(middleware ...MiddlewareFunc)
	// Middleware 返回注册的所有中间件
	Middleware() []MiddlewareFunc
}

// MiddlewareComposer 中间件合成器接口
type MiddlewareComposer interface {
	// Compose 将注册的所有中间件合并成一个中间件
	Compose() MiddlewareFunc
}

type MiddlewareConfigurator interface {
	// ToMiddleware 将实例转换成中间件函数
	ToMiddleware() MiddlewareFunc
}

// Renderer is the interface that wraps the Render function.
type Renderer interface {
	Render(c Context, w io.Writer, name string, data any) error
}

// Validator is the interface that wraps the Validate function.
type Validator interface {
	Validate(i any) error
}

// Map defines a generic map of type `map[string]any`.
type Map map[string]any

type Slim struct {
	// startupMutex is mutex to lock Server instance access during server configuration and startup. Useful for to get
	// listener address info (on which interface/port was listener bound) without having data races.
	startupMutex sync.RWMutex

	middleware []MiddlewareFunc

	router        Router
	routers       map[string]Router
	routerCreator func(s *Slim) Router

	contextPool               sync.Pool
	contextPathParamAllocSize int

	negotiator *Negotiator

	NewContextFunc       func(pathParamAllocSize int) EditableContext // 自定义 `slim.Context` 构造函数
	ErrorHandler         ErrorHandlerFunc
	Filesystem           fs.FS // 静态资源文件系统，默认值 `os.DirFS(".")`。
	Binder               Binder
	Validator            Validator
	Renderer             Renderer // 自定义错误处理函数
	JSONSerializer       Serializer
	XMLSerializer        Serializer
	Logger               log.Logger
	Server               *http.Server
	TLSServer            *http.Server
	Listener             net.Listener
	TLSListener          net.Listener
	StdLogger            *stdLog.Logger
	AutoTLSManager       autocert.Manager
	DisableHTTP2         bool
	HideBanner           bool
	HidePort             bool
	ListenerNetwork      string
	Debug                bool     // 是否开启调试模式
	MultipartMemoryLimit int64    // 文件上传大小限制
	PrettyIndent         string   // json/xml 格式化缩进
	JSONPCallbacks       []string // jsonp 回调函数
}

func Classic() *Slim {
	s := New()
	s.Use(Logging())
	s.Use(Recovery())
	s.Use(Static("public"))
	return s
}

func New() *Slim {
	s := &Slim{
		routers:              make(map[string]Router),
		negotiator:           NewNegotiator(10, nil),
		Server:               new(http.Server),
		TLSServer:            new(http.Server),
		AutoTLSManager:       autocert.Manager{Prompt: autocert.AcceptTOS},
		ListenerNetwork:      "tcp",
		NewContextFunc:       nil,
		ErrorHandler:         ErrorHandler,
		Filesystem:           os.DirFS("."),
		Binder:               &DefaultBinder{},
		Validator:            nil,
		Renderer:             nil,
		JSONSerializer:       &JSONSerializer{},
		XMLSerializer:        &XMLSerializer{},
		Logger:               log.WithPrefix(""),
		Debug:                true,
		MultipartMemoryLimit: 32 << 20, // 32 MB
		PrettyIndent:         "  ",
		JSONPCallbacks:       []string{"jsonp", "callback"},
	}
	s.Server.Handler = s
	s.TLSServer.Handler = s
	s.router = s.NewRouter()
	s.contextPool.New = func() any {
		if s.NewContextFunc != nil {
			return s.NewContextFunc(s.contextPathParamAllocSize)
		}
		return s.NewContext(nil, nil)
	}
	return s
}

func (s *Slim) NewContext(w http.ResponseWriter, r *http.Request) Context {
	p := make(PathParams, s.contextPathParamAllocSize)
	c := &context{
		request:       r,
		response:      nil,
		allowsMethods: make([]string, 0),
		store:         make(Map),
		slim:          s,
		pathParams:    &p,
		matchType:     RouteMatchUnknown,
		route:         nil,
	}
	if w != nil && r != nil {
		c.response = NewResponseWriter(r.Method, w)
	}
	return c
}

func (s *Slim) NewRouter() Router {
	if s.routerCreator != nil {
		return s.routerCreator(s)
	}
	r := NewRouter(RouterConfig{}).(*defaultRouter)
	r.slim = s
	return r
}

// Router 返回默认路由器
func (s *Slim) Router() Router {
	return s.router
}

// Routers 返回 vhost 的 `host => router` 映射
func (s *Slim) Routers() map[string]Router {
	return s.routers
}

// RouterFor 返回与指定 `host` 相关的路由器
func (s *Slim) RouterFor(host string) Router {
	return s.routers[host]
}

// ResetRouterCreator 重置路由器创建函数。
// 注意：会立即重新创建默认路由器，并且 vhost 路由器会被清除。
func (s *Slim) ResetRouterCreator(creator func(s *Slim) Router) {
	s.routerCreator = creator
	s.router = creator(s)
	clear(s.routers)
}

// Use 注册全局中间件
func (s *Slim) Use(middleware ...MiddlewareFunc) {
	s.middleware = append(s.middleware, middleware...)
}

// Host 通过提供名称和中间件函数创建对应 `host` 的路由器实例
func (s *Slim) Host(name string, middleware ...MiddlewareFunc) Router {
	router := s.NewRouter()
	router.Use(middleware...)
	s.routers[name] = router
	return router
}

// Group 实现路由分组注册，实际调用 `RouteCollector.Route` 实现
func (s *Slim) Group(fn func(sub RouteCollector)) {
	s.router.Group(fn)
}

// Route 以指定前缀实现路由分组注册
func (s *Slim) Route(prefix string, fn func(sub RouteCollector)) {
	s.router.Route(prefix, fn)
}

// Some registers a new route for multiple HTTP methods and path with matching
// handler in the router. Panics on error.
func (s *Slim) Some(methods []string, pattern string, h HandlerFunc) Route {
	return s.router.Some(methods, pattern, h)
}

// Any registers a new route for all supported HTTP methods and path with matching
// handler in the router. Panics on error.
func (s *Slim) Any(pattern string, h HandlerFunc) Route {
	return s.router.Any(pattern, h)
}

// CONNECT registers a new CONNECT route for a path with matching handler in the
// router with optional route-level middleware.
func (s *Slim) CONNECT(path string, h HandlerFunc) Route {
	return s.router.CONNECT(path, h)
}

// DELETE registers a new DELETE route for a path with matching handler in the router
// with optional route-level middleware.
func (s *Slim) DELETE(path string, h HandlerFunc) Route {
	return s.router.DELETE(path, h)
}

// GET registers a new GET route for a path with matching handler in the router
// with optional route-level middleware.
func (s *Slim) GET(path string, h HandlerFunc) Route {
	return s.router.GET(path, h)
}

// HEAD registers a new HEAD route for a path with matching handler in the
// router with optional route-level middleware.
func (s *Slim) HEAD(path string, h HandlerFunc) Route {
	return s.router.HEAD(path, h)
}

// OPTIONS registers a new OPTIONS route for a path with matching handler in the
// router with optional route-level middleware.
func (s *Slim) OPTIONS(path string, h HandlerFunc) Route {
	return s.router.OPTIONS(path, h)
}

// PATCH registers a new PATCH route for a path with matching handler in the
// router with optional route-level middleware.
func (s *Slim) PATCH(path string, h HandlerFunc) Route {
	return s.router.PATCH(path, h)
}

// POST registers a new POST route for a path with matching handler in the
// router with optional route-level middleware.
func (s *Slim) POST(path string, h HandlerFunc) Route {
	return s.router.POST(path, h)
}

// PUT registers a new PUT route for a path with matching handler in the
// router with optional route-level middleware.
func (s *Slim) PUT(path string, h HandlerFunc) Route {
	return s.router.PUT(path, h)
}

// TRACE registers a new TRACE route for a path with matching handler in the
// router with optional route-level middleware.
func (s *Slim) TRACE(path string, h HandlerFunc) Route {
	return s.router.TRACE(path, h)
}

// Static registers a new route with path prefix to serve static files
// from the provided root directory. Panics on error.
func (s *Slim) Static(prefix, root string) Route {
	return s.router.Static(prefix, root)
}

// File registers a new route with a path to serve a static file.
// Panics on error.
func (s *Slim) File(path, file string) Route {
	return s.router.File(path, file)
}

// Negotiator 返回内容协商工具
func (s *Slim) Negotiator() *Negotiator {
	return s.negotiator
}

// SetNegotiator 设置自定义内容协商工具
func (s *Slim) SetNegotiator(negotiator *Negotiator) {
	s.negotiator = negotiator
}

// AcquireContext returns 自上下文缓存池中返回一个空闲的 `mux.Context` 实例。
// 在不需要的时候，必须通过调用 `Mux.ReleaseContext` 方法归还该上下文。
func (s *Slim) AcquireContext() Context {
	return s.contextPool.Get().(Context)
}

// ReleaseContext 归还通过 `Mux.AcquireContext` 获取的 `mux.Context` 实例
// 到上下文缓存池中.
func (s *Slim) ReleaseContext(c Context) {
	s.contextPool.Put(c)
}

// ServeHTTP 实现 `http.Handler` 接口
func (s *Slim) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := s.AcquireContext().(EditableContext)
	c.Reset(w, r)
	router := s.findRouter(r)
	stack := append(s.middleware, router.Middleware()...)
	mw := Compose(stack...)
	var err error
	if mw == nil {
		err = s.findHandler(c, router)(c)
	} else {
		err = mw(c, func(cc Context) error {
			return s.findHandler(c, router)(cc)
		})
	}
	if err != nil {
		s.handleError(c, err)
	}
	s.ReleaseContext(c)
}

// findRouter 通过请求中的原始域名确定路由
func (s *Slim) findRouter(r *http.Request) Router {
	if len(s.routers) == 0 {
		return s.router
	}
	// 非标准报头，但常用于确定客户端发起的请求中使用的初始域名（如反向代理），
	// https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/X-Forwarded-Host
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		// RFC 7239
		// https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Headers/Forwarded
		forwarded := r.Header.Get("Forwarded")
		if forwarded != "" {
			for _, forwardedPair := range strings.Split(forwarded, ";") {
				if tv := strings.SplitN(forwardedPair, "=", 2); len(tv) == 2 {
					token, value := tv[0], tv[1]
					token = strings.TrimSpace(token)
					value = strings.TrimSpace(strings.Trim(value, `"`))
					if strings.ToLower(token) == "host" {
						host = value
						break
					}
				}
			}
		}
		if host == "" {
			host = r.Host
		}
	}
	// 指定路由 `dev.example.com`
	if router, ok := s.routers[strings.ToLower(host)]; ok {
		return router
	}
	// 通配路由 `*.example.com`
	parts := strings.Split(host, ".")
	if len(parts) > 1 {
		wildcard := append([]string{"*"}, parts[1:]...)
		host = strings.Join(wildcard, ".")
	} else {
		host = strings.Join(parts, ".")
	}
	if router, ok := s.routers[strings.ToLower(host)]; ok {
		return router
	}
	// 使用默认路由
	return s.router
}

func (s *Slim) findHandler(c EditableContext, router Router) HandlerFunc {
	r := c.Request()
	params := c.RawPathParams()
	match := router.Match(r, params)
	c.SetRawPathParams(params)
	c.SetAllowsMethods(match.AllowMethods)
	c.SetRouteInfo(match.RouteInfo)
	c.SetRouteMatchType(match.Type)
	if i, ok := c.(interface{ SetRouter(Router) }); ok {
		i.SetRouter(router)
	}
	return match.Handler
}

// handleError 处理路由执行错误
func (s *Slim) handleError(c Context, err error) {
	if err == nil {
		return
	}
	if info := c.RouteInfo(); info != nil {
		// 优先使用路由收集器中定义的错误处理器处理错误
		collector := info.Collector()
		for collector != nil {
			if i, ok := collector.(interface{ HandleError(Context, error) }); ok {
				i.HandleError(c, err)
				return
			}
			collector = collector.Parent()
		}
		// 路由器中定义的错误处理器次之
		router := info.Router()
		if i, ok := router.(interface{ HandleError(Context, error) }); ok {
			i.HandleError(c, err)
			return
		}
	}
	// 最后使用上下文的错误处理器。
	c.Error(err)
}

// Start starts an HTTP server.
func (s *Slim) Start(address string) error {
	s.startupMutex.Lock()
	s.Server.Addr = address
	if err := s.configureServer(s.Server); err != nil {
		s.startupMutex.Unlock()
		return err
	}
	s.startupMutex.Unlock()
	return s.Server.Serve(s.Listener)
}

// StartTLS starts an HTTPS server.
// If `certFile` or `keyFile` is `string`, the values are treated as file paths.
// If `certFile` or `keyFile` is `[]byte`, the values are treated as the certificate or key as-is.
func (s *Slim) StartTLS(address string, certFile, keyFile interface{}) (err error) {
	s.startupMutex.Lock()
	var cert []byte
	if cert, err = filepathOrContent(certFile); err != nil {
		s.startupMutex.Unlock()
		return
	}

	var key []byte
	if key, err = filepathOrContent(keyFile); err != nil {
		s.startupMutex.Unlock()
		return
	}

	srv := s.TLSServer
	srv.TLSConfig = new(tls.Config)
	srv.TLSConfig.Certificates = make([]tls.Certificate, 1)
	if srv.TLSConfig.Certificates[0], err = tls.X509KeyPair(cert, key); err != nil {
		s.startupMutex.Unlock()
		return
	}

	s.configureTLS(address)
	if err := s.configureServer(srv); err != nil {
		s.startupMutex.Unlock()
		return err
	}
	s.startupMutex.Unlock()
	return srv.Serve(s.TLSListener)
}

func filepathOrContent(fileOrContent interface{}) (content []byte, err error) {
	switch v := fileOrContent.(type) {
	case string:
		return os.ReadFile(v)
	case []byte:
		return v, nil
	default:
		return nil, ErrInvalidCertOrKeyType
	}
}

// StartAutoTLS starts an HTTPS server using certificates automatically installed from https://letsencrypt.org.
func (s *Slim) StartAutoTLS(address string) error {
	s.startupMutex.Lock()
	srv := s.TLSServer
	srv.TLSConfig = new(tls.Config)
	srv.TLSConfig.GetCertificate = s.AutoTLSManager.GetCertificate
	srv.TLSConfig.NextProtos = append(srv.TLSConfig.NextProtos, acme.ALPNProto)

	s.configureTLS(address)
	if err := s.configureServer(srv); err != nil {
		s.startupMutex.Unlock()
		return err
	}
	s.startupMutex.Unlock()
	return srv.Serve(s.TLSListener)
}

func (s *Slim) configureTLS(address string) {
	srv := s.TLSServer
	srv.Addr = address
	if !s.DisableHTTP2 {
		srv.TLSConfig.NextProtos = append(srv.TLSConfig.NextProtos, "h2")
	}
}

// StartServer starts a custom http server.
func (s *Slim) StartServer(srv *http.Server) (err error) {
	s.startupMutex.Lock()
	if err := s.configureServer(srv); err != nil {
		s.startupMutex.Unlock()
		return err
	}
	if srv.TLSConfig != nil {
		s.startupMutex.Unlock()
		return srv.Serve(s.TLSListener)
	}
	s.startupMutex.Unlock()
	return srv.Serve(s.Listener)
}

func (s *Slim) configureServer(srv *http.Server) error {
	// Setup
	c := newColor(s.Logger.Output())
	srv.ErrorLog = s.StdLogger
	srv.Handler = s
	if s.Debug {
		s.Logger.SetLevel(log.LevelDebug)
	}

	if !s.HideBanner {
		c.Printf(banner, c.Red("v"+Version), c.Blue(website))
	}

	if srv.TLSConfig == nil {
		if s.Listener == nil {
			l, err := newListener(srv.Addr, s.ListenerNetwork)
			if err != nil {
				return err
			}
			s.Listener = l
		}
		if !s.HidePort {
			c.Printf("⇨ http server started on %s\n", c.Green(s.Listener.Addr()))
		}
		return nil
	}
	if s.TLSListener == nil {
		l, err := newListener(srv.Addr, s.ListenerNetwork)
		if err != nil {
			return err
		}
		s.TLSListener = tls.NewListener(l, srv.TLSConfig)
	}
	if !s.HidePort {
		c.Printf("⇨ https server started on %s\n", c.Green(s.TLSListener.Addr()))
	}
	return nil
}

// ListenerAddr returns net.Addr for Listener
func (s *Slim) ListenerAddr() net.Addr {
	s.startupMutex.RLock()
	defer s.startupMutex.RUnlock()
	if s.Listener == nil {
		return nil
	}
	return s.Listener.Addr()
}

// TLSListenerAddr returns net.Addr for TLSListener
func (s *Slim) TLSListenerAddr() net.Addr {
	s.startupMutex.RLock()
	defer s.startupMutex.RUnlock()
	if s.TLSListener == nil {
		return nil
	}
	return s.TLSListener.Addr()
}

// StartH2CServer starts a custom http/2 server with h2c (HTTP/2 Cleartext).
func (s *Slim) StartH2CServer(address string, h2s *http2.Server) error {
	s.startupMutex.Lock()
	// Setup
	c := newColor(s.Logger.Output())
	srv := s.Server
	srv.Addr = address
	srv.ErrorLog = s.StdLogger
	srv.Handler = h2c.NewHandler(s, h2s)
	if s.Debug {
		s.Logger.SetLevel(log.LevelDebug)
	}

	if !s.HideBanner {
		c.Printf(banner, c.Red("v"+Version), c.Blue(website))
	}

	if s.Listener == nil {
		l, err := newListener(srv.Addr, s.ListenerNetwork)
		if err != nil {
			s.startupMutex.Unlock()
			return err
		}
		s.Listener = l
	}
	if !s.HidePort {
		c.Printf("⇨ http server started on %s\n", c.Green(s.Listener.Addr()))
	}
	s.startupMutex.Unlock()
	return srv.Serve(s.Listener)
}

// Close immediately stops the server.
// It internally calls `http.Server#Close()`.
func (s *Slim) Close() error {
	s.startupMutex.Lock()
	defer s.startupMutex.Unlock()
	if err := s.TLSServer.Close(); err != nil {
		return err
	}
	return s.Server.Close()
}

// Shutdown stops the server gracefully.
// It internally calls `http.Server#Shutdown()`.
func (s *Slim) Shutdown(ctx stdctx.Context) error {
	s.startupMutex.Lock()
	defer s.startupMutex.Unlock()
	if err := s.TLSServer.Shutdown(ctx); err != nil {
		return err
	}
	return s.Server.Shutdown(ctx)
}

// WrapHandler wraps `http.Handler` into `echo.HandlerFunc`.
func WrapHandler(h http.Handler) HandlerFunc {
	return func(c Context) error {
		h.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// WrapMiddleware wraps `func(http.Handler) http.Handler` into `echo.MiddlewareFunc`
func WrapMiddleware(m func(http.Handler) http.Handler) MiddlewareFunc {
	return func(c Context, next HandlerFunc) (err error) {
		m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.SetRequest(r)
			c.SetResponse(NewResponseWriter(r.Method, w))
			err = next(c)
		})).ServeHTTP(c.Response(), c.Request())
		return
	}
}

// ErrorHandler 默认错误处理函数
func ErrorHandler(c Context, err error) {
	if c.Written() {
		c.Logger().Error(err.Error())
		return
	}
	// TODO(hupeh): 根据 Accept 报头返回对应的格式
	if errors.Is(err, ErrNotFound) {
		http.NotFound(c.Response(), c.Request())
	} else if errors.Is(err, ErrMethodNotAllowed) {
		c.SetHeader("Allow", c.AllowsMethods()...)
		http.Error(c.Response(), http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	} else {
		http.Error(c.Response(), err.Error(), http.StatusInternalServerError)
	}
}

func NotFoundHandler(_ Context) error {
	return ErrNotFound
}

func MethodNotAllowedHandler(_ Context) error {
	return ErrMethodNotAllowed
}

func newColor(w io.Writer) *color.Color {
	if ww, ok := w.(*log.Writer); ok {
		return ww.Color
	}
	return color.NewWithOutput(w)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g., closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	if c, err = ln.AcceptTCP(); err != nil {
		return
	} else if err = c.(*net.TCPConn).SetKeepAlive(true); err != nil {
		return
	}
	// Ignore error from setting the KeepAlivePeriod as some systems, such as
	// OpenBSD, do not support setting TCP_USER_TIMEOUT on IPPROTO_TCP
	_ = c.(*net.TCPConn).SetKeepAlivePeriod(3 * time.Minute)
	return
}

func newListener(address, network string) (*tcpKeepAliveListener, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrInvalidListenerNetwork
	}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	return &tcpKeepAliveListener{l.(*net.TCPListener)}, nil
}
