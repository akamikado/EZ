package stdlib

import "github.com/marshallburns/ez/pkg/object"

var HttpBuiltins = map[string]*object.Builtin{
	// Basic Requests
	"http.get": {},
	"http.post": {},
	"http.put": {},
	"http.delete": {},
	"http.patch": {},

	// Advanced Requests
	"http.request": {},

	// Url Utilities
	"http.encode_url": {},
	"http.decode_url": {},
	"http.build_query": {},

	// JSON Helper
	"http.json_body": {},
}
