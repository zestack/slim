package slim

import (
	"fmt"
	"mime"
	"strings"
)

type ctype struct {
	typ string
	sub string
}

func (c *ctype) is(typ, sub string) bool {
	if c.typ != typ {
		return false
	}
	if sub != c.sub {
		return sub == "*"
	}
	return true
}

// multipart/form-data; boundary=----WebKitFormBoundaryaCNSUNoouK7Epo6s
// application/json; charset=UTF-8
func parseContentType(s string) (*ctype, error) {
	rangeParams := strings.Split(s, ";")
	typeSubtype := strings.Split(rangeParams[0], "/")
	// typeSubtype should have a length of exactly two.
	if len(typeSubtype) > 2 {
		return nil, fmt.Errorf("slim: invalid content type '%s'", s)
	} else {
		typeSubtype = append(typeSubtype, "*")
	}
	// Sanitize typeSubtype.
	main := strings.TrimSpace(typeSubtype[0])
	sub := strings.TrimSpace(typeSubtype[1])
	if main == "" {
		return nil, fmt.Errorf("slim: invalid content type '%s'", s)
	} else {
		main = strings.ToLower(strings.TrimSpace(main))
	}
	if sub == "" {
		sub = "*"
	} else {
		sub = strings.ToLower(strings.TrimSpace(sub))
	}
	return &ctype{main, sub}, nil
}

func typeis(value string, types ...string) (string, error) {
	cty, err := parseContentType(value)
	if err != nil {
		return "", err
	}
	if cty.sub == "*" {
		return "", fmt.Errorf("slim: invalid content type '%s'", value)
	}
	for _, typ := range types {
		s := typ
		switch typ {
		case "jsonp":
			if cty.is("application", "javascript") {
				return typ, nil
			}
		case "xml":
			if cty.is("application", "xml") {
				return typ, nil
			}
			if cty.is("text", "xml") {
				return typ, nil
			}
		case "form":
			if cty.is("multipart", "form-data") {
				return typ, nil
			}
			if cty.is("application", "x-www-form-urlencoded") {
				return typ, nil
			}
		case "protobuf", "msgpack":
			if cty.is("application", typ) {
				return typ, nil
			}
		case "text", "string":
			if cty.is("text", "plain") {
				return typ, nil
			}
		default:
			if !strings.Contains(typ, "/") {
				value := mime.TypeByExtension("." + typ)
				if value != "" {
					s = value
				} else {
					continue
				}
			}
		}

		x, ex := parseContentType(s)
		if ex != nil {
			continue
		}
		if cty.is(x.typ, x.sub) {
			return typ, nil
		}
	}
	return "", nil
}
