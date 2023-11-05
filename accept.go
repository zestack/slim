package slim

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type cache struct {
	hint  int
	slice AcceptSlice
}

// Negotiator An HTTP content negotiator
//
//	Accept: <MIME_type>/<MIME_subtype>
//	Accept: <MIME_type>/*
//	Accept: */*
//	Accept: text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8
type Negotiator struct {
	capacity int // for cache
	caches   map[string]*cache
}

func NewNegotiator(capacity int) *Negotiator {
	if capacity <= 0 {
		capacity = 10
	}
	return &Negotiator{
		capacity: capacity,
		caches:   make(map[string]*cache),
	}
}

func (n *Negotiator) Slice(header string) AcceptSlice {
	if c, ok := n.caches[header]; ok {
		c.hint++
		return c.slice
	}
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
	slice := newSlice(header)
	n.caches[header] = &cache{1, slice}
	return slice
}

func (n *Negotiator) Is(header string, expects ...string) bool {
	return n.Slice(header).Is(expects...)
}

func (n *Negotiator) Type(header string, expects ...string) string {
	return n.Slice(header).Type(expects...)
}

// Accept represents a parsed `Accept` header.
type Accept struct {
	Type, Subtype string
	Q             float64
	mime          string
}

func (a *Accept) Mime() string {
	if a.mime == "" {
		a.mime = a.Type + "/" + a.Subtype
	}
	return a.mime
}

// AcceptSlice is a slice of accept.
type AcceptSlice []Accept

// newSlice parses an HTTP Accept header and returns AcceptSlice, sorted in
// decreasing order of preference.  If the header lists multiple types that
// have the same level of preference (same specificity of a type and subtype,
// same qvalue, and same number of extensions), the type that was listed
// in the header first comes in the returned value.
//
// See http://www.w3.org/Protocols/rfc2616/rfc2616-sec14 for more information.
func newSlice(header string) AcceptSlice {
	mediaRanges := strings.Split(header, ",")
	accepted := make(AcceptSlice, 0, len(mediaRanges))
	for _, mediaRange := range mediaRanges {
		rangeParams, typeSubtype, err := parseMediaRange(mediaRange)
		if err != nil {
			continue
		}
		item := Accept{
			Type:    typeSubtype[0],
			Subtype: typeSubtype[1],
			Q:       1.0,
		}
		// If there is only one rangeParams, we can stop here.
		if len(rangeParams) == 1 {
			accepted = append(accepted, item)
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
				item.Q = qval
				//break // 不跳过，检查 validParams
			}
		}
		if validParams {
			accepted = append(accepted, item)
		}
	}
	sort.Sort(accepted)
	return accepted
}

// Len implements the Len() method of the Sort interface.
func (a AcceptSlice) Len() int {
	return len(a)
}

// Less implements the Less() method of the Sort interface.  Elements are
// sorted in order of decreasing preference.
func (a AcceptSlice) Less(i, j int) bool {
	// Higher qvalues come first.
	if a[i].Q > a[j].Q {
		return true
	} else if a[i].Q < a[j].Q {
		return false
	}

	// Specific types come before wildcard types.
	if a[i].Type != "*" && a[j].Type == "*" {
		return true
	} else if a[i].Type == "*" && a[j].Type != "*" {
		return false
	}

	// Specific subtypes come before wildcard subtypes.
	if a[i].Subtype != "*" && a[j].Subtype == "*" {
		return true
	} else if a[i].Subtype == "*" && a[j].Subtype != "*" {
		return false
	}

	return false
}

// Swap implements the Swap() method of the Sort interface.
func (a AcceptSlice) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a AcceptSlice) Is(expect ...string) bool {
	for _, e := range expect {
		for _, s := range a {
			if e == s.Mime() {
				return true
			}
		}
	}
	return false
}

func (a AcceptSlice) Type(expects ...string) string {
	if len(expects) == 0 {
		return ""
	}
	var fuzzies [][2]string
	for _, expect := range expects {
		switch expect {
		case "html":
			if a.Is(MIMETextHTML) {
				return expect
			}
			fuzzies = append(fuzzies, [2]string{expect, "text/*"})
		case "json":
			if a.Is(MIMEApplicationJSON) {
				return expect
			}
			fuzzies = append(fuzzies, [2]string{expect, "text/*"})
		case "jsonp":
			if a.Is(MIMEApplicationJavaScript) {
				return expect
			}
		case "xml":
			if a.Is(MIMEApplicationXML, MIMETextXML) {
				return expect
			}
			fuzzies = append(fuzzies, [2]string{expect, "text/*"})
		case "form":
			if a.Is(MIMEMultipartForm, MIMEApplicationForm) {
				return expect
			}
		case "protobuf":
			if a.Is(MIMEApplicationProtobuf) {
				return expect
			}
		case "msgpack":
			if a.Is(MIMEApplicationMsgpack) {
				return expect
			}
		case "text", "string":
			if a.Is(MIMETextPlain) {
				return expect
			}
		default:
			_, typeSubtype, err := parseMediaRange(expect)
			if err != nil {
				continue
			}
			if a.Is(typeSubtype[0] + "/" + typeSubtype[1]) {
				return expect
			}
			//if typeSubtype[0] == "text" {
			//	fuzzies = append(fuzzies, [2]string{expect, "text/*"})
			//}
			fuzzies = append(fuzzies, [2]string{expect, typeSubtype[0] + "/*"})
		}
	}
	if fuzzies != nil {
		for _, f := range fuzzies {
			if a.Is(f[1]) {
				return f[0]
			}
		}
	}
	if a.Is("*/*") {
		return expects[0]
	}
	return ""
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
