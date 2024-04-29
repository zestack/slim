package slim

import (
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sync/singleflight"
)

type cache struct {
	hint  int
	slice AcceptSlice
}

// Negotiator An HTTP content negotiator
type Negotiator struct {
	// 缓存容量
	capacity int
	// 有些时候，解析出来的 Accept 并
	// 不是 W3C 所定义的标准的值，我们
	// 通过该函数将其重写成标准格式的值。
	onParse func(*Accept)
	// 内容协商的报头很少变化，可以使用缓存优化，
	// 不需要每次解析
	caches map[string]*cache
	// 用于合并解析，优化并发
	sfg singleflight.Group
}

func NewNegotiator(capacity int, onParse func(accept *Accept)) *Negotiator {
	if capacity <= 0 {
		capacity = 10
	}
	if onParse == nil {
		onParse = onAcceptParsed
	}
	return &Negotiator{
		capacity: capacity,
		onParse:  onParse,
		caches:   make(map[string]*cache),
	}
}

func (n *Negotiator) Slice(header string) AcceptSlice {
	v, _, _ := n.sfg.Do(header, func() (any, error) {
		if c, ok := n.caches[header]; ok {
			c.hint++
			return c.slice, nil
		}
		n.overflow()
		c := n.parse(header)
		return c, nil
	})
	return v.(AcceptSlice)
}

func (n *Negotiator) overflow() {
	if len(n.caches) >= n.capacity {
		var s string
		var hint int
		for i, x := range n.caches {
			if hint == 0 || hint < x.hint {
				hint = x.hint
				s = i
			}
		}
		delete(n.caches, s)
	}
}

func (n *Negotiator) parse(header string) AcceptSlice {
	slice := newSlice(header, n.onParse)
	n.caches[header] = &cache{1, slice}
	return slice
}

func (n *Negotiator) Charset(r *http.Request, charsets ...string) string {
	return n.Accepts(r.Header.Get("Accept-Charset"), charsets...)
}

func (n *Negotiator) Encoding(r *http.Request, encodings ...string) string {
	return n.Accepts(r.Header.Get("Accept-Encoding"), encodings...)
}

func (n *Negotiator) Language(r *http.Request, languages ...string) string {
	return n.Accepts(r.Header.Get("Accept-Language"), languages...)
}

func (n *Negotiator) Type(r *http.Request, types ...string) string {
	var keys []string
	var ctypes []string
	for _, typ := range types {
		keys = append(keys, typ)
		switch typ {
		case "jsonp":
			ctypes = append(ctypes, MIMEApplicationJavaScript)
		case "json":
			ctypes = append(ctypes, MIMEApplicationJSON)
		case "xml":
			keys = append(keys, typ[:])
			ctypes = append(ctypes, MIMEApplicationXML, MIMETextXML)
		case "form":
			keys = append(keys, typ)
			ctypes = append(ctypes, MIMEMultipartForm, MIMEApplicationForm)
		case "protobuf":
			ctypes = append(ctypes, MIMEApplicationProtobuf)
		case "msgpack":
			ctypes = append(ctypes, MIMEApplicationMsgpack)
		case "text", "string":
			ctypes = append(ctypes, MIMETextPlain)
		default:
			if !strings.Contains(typ, "/") {
				value := mime.TypeByExtension("." + typ)
				if value != "" {
					ctypes = append(ctypes, value)
					continue
				}
			}
			ctypes = append(ctypes, typ[:])
		}
	}
	s := n.Slice(r.Header.Get("Accept"))
	_, i, _ := s.Negotiate(ctypes...)
	if i > -1 {
		return keys[i]
	}
	return ""
}

func (n *Negotiator) Accepts(header string, ctypes ...string) string {
	s := n.Slice(header)
	negotiated, _, _ := s.Negotiate(ctypes...)
	return negotiated
}

// Accept represents a parsed `Accept(-Charset|-Encoding|-Language)` header.
type Accept struct {
	Type       string
	Subtype    string
	Quality    float64
	Extensions map[string]any
}

// AcceptSlice is a slice of accept.
type AcceptSlice []Accept

func onAcceptParsed(*Accept) {}

// 解析 HTTP 的 Accept(-Charset|-Encoding|-Language) 报头，
// 返回 AcceptSlice，该结果是根据值的类型和权重因子按照降序排列的，
// 如果类型一致且权重一致，则使用出场的先后顺序排列。
//
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec14
func newSlice(header string, onParse func(*Accept)) AcceptSlice {
	mediaRanges := strings.Split(header, ",")
	accepted := make(AcceptSlice, 0, len(mediaRanges))
	for _, mediaRange := range mediaRanges {
		rangeParams, typeSubtype, err := parseMediaRange(mediaRange)
		if err != nil {
			continue
		}

		accept := Accept{
			Type:       typeSubtype[0],
			Subtype:    typeSubtype[1],
			Quality:    1.0,
			Extensions: make(map[string]any),
		}

		// If there is only one rangeParams, we can stop here.
		if len(rangeParams) == 1 {
			onParse(&accept)
			accepted = append(accepted, accept)
			continue
		}

		// Validate the rangeParams.
		validParams := true
		for _, v := range rangeParams[1:] {
			nameVal := strings.SplitN(v, "=", 2)
			if len(nameVal) != 2 {
				validParams = false
				break
			}
			nameVal[1] = strings.TrimSpace(nameVal[1])
			if name := strings.TrimSpace(nameVal[0]); name == "q" {
				qval, err := strconv.ParseFloat(nameVal[1], 64)
				if err != nil || qval < 0 {
					validParams = false
					break
				}
				if qval > 1.0 {
					qval = 1.0
				}
				accept.Quality = qval
			} else {
				accept.Extensions[name] = nameVal[1]
			}
		}

		if validParams {
			onParse(&accept)
			accepted = append(accepted, accept)
		}
	}
	sort.Sort(accepted)
	return accepted
}

// Len implements the Len() method of the Sort interface.
func (slice AcceptSlice) Len() int {
	return len(slice)
}

// Less implements the Less() method of the Sort interface.  Elements are
// sorted in order of decreasing preference.
func (slice AcceptSlice) Less(i, j int) bool {
	// Higher qvalues come first.
	if slice[i].Quality > slice[j].Quality {
		return true
	} else if slice[i].Quality < slice[j].Quality {
		return false
	}

	// Specific types come before wildcard types.
	if slice[i].Type != "*" && slice[j].Type == "*" {
		return true
	} else if slice[i].Type == "*" && slice[j].Type != "*" {
		return false
	}

	// Specific subtypes come before wildcard subtypes.
	if slice[i].Subtype != "*" && slice[j].Subtype == "*" {
		return true
	} else if slice[i].Subtype == "*" && slice[j].Subtype != "*" {
		return false
	}

	return false
}

// Swap implements the Swap() method of the Sort interface.
func (slice AcceptSlice) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

// Negotiate returns a type that is accepted by both the AcceptSlice, and the
// list of types provided. If no common types are found, an empty string is
// returned.
func (slice AcceptSlice) Negotiate(ctypes ...string) (string, int, error) {
	if len(ctypes) == 0 {
		return "", -1, nil
	}

	typeSubtypes := make([][]string, 0, len(ctypes))
	for i, v := range ctypes {
		_, ts, err := parseMediaRange(v)
		if err != nil {
			return "", -1, err
		}
		if ts[0] == "*" && ts[1] == "*" {
			return v, i, nil
		}
		typeSubtypes = append(typeSubtypes, ts)
	}

	// 由于 slice 是根据权重排序的，返回的值
	// 当然也要依据权重来返回，所以先查看 slice，
	// 然后循环 ctypes。
	for _, a := range slice {
		for i, ts := range typeSubtypes {
			if ((a.Type == ts[0] || a.Type == "*") && (a.Subtype == ts[1] || a.Subtype == "*")) ||
				(ts[0] == "*" && ts[1] == a.Subtype) ||
				(ts[0] == a.Type && ts[1] == "*") {
				return ctypes[i], i, nil
			}
		}
	}
	return "", -1, nil
}

// Accepts returns true if the provided type is accepted.
func (slice AcceptSlice) Accepts(ctype string) bool {
	t, i, err := slice.Negotiate(ctype)
	if t == "" || err != nil || i == -1 {
		return false
	}
	return true
}

// parseMediaRange parses the provided media range, and on success returns the
// parsed range params and type/subtype pair.
func parseMediaRange(mediaRange string) (rangeParams, typeSubtype []string, err error) {
	rangeParams = strings.Split(mediaRange, ";")
	typeSubtype = strings.Split(rangeParams[0], "/")
	// typeSubtype should have a length of exactly two.
	if len(typeSubtype) > 2 {
		err = fmt.Errorf("slim: invalid accept type '%s'", rangeParams[0])
		return
	} else {
		typeSubtype = append(typeSubtype, "*")
	}
	// Sanitize typeSubtype.
	typeSubtype[0] = strings.TrimSpace(typeSubtype[0])
	typeSubtype[1] = strings.TrimSpace(typeSubtype[1])
	if typeSubtype[0] == "" {
		typeSubtype[0] = "*"
	}
	if typeSubtype[1] == "" {
		typeSubtype[1] = "*"
	}
	return
}
