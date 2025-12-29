package stdlib

import (
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/marshallburns/ez/pkg/object"
)

var HttpBuiltins = map[string]*object.Builtin{
	// Basic Requests
	"http.get": {
		Fn: func(args ...object.Object) object.Object {
			if len(args) != 1 {
				return &object.Error{Code: "E7001", Message: "http.get(): wrong number of arguments"}
			}

			url, ok := args[0].(*object.String)
			if !ok {
				return &object.Error{Code: "E7003", Message: "http.get(): argument must be a string"}
			}
			res, err := http.Get(url.Value)
			if err != nil {
				return &object.ReturnValue{Values: []object.Object{
					&object.Nil{},
					createHttpError("E14002", "http.get(): request failed"),
				}}
			}
			defer res.Body.Close()

			body, err := io.ReadAll(res.Body)
			if err != nil {
				fmt.Println(err)
				return &object.ReturnValue{Values: []object.Object{
					&object.Nil{},
					createHttpError("E14002", "http.get(): request failed"),
				}}
			}

			headers := object.NewMap()
			for key, vals := range res.Header {
				var headerKey = object.String{Value: key}
				var headerVal []object.Object
				for _, val := range vals {
					headerVal = append(headerVal, &object.String{Value: val})
				} 
				headers.Set(&headerKey, 
					&object.Array{ElementType: "string", Mutable: false, Elements: headerVal})
			}

			return &object.ReturnValue{
				Values: []object.Object{
					newHttpResponse(map[string]object.Object{
						"status": &object.Integer{Value: big.NewInt(int64(res.StatusCode))},
						"body": &object.String{Value: string(body)},
						"headers": headers,
					}),
					&object.Nil{},
				},
			}
		},
	},

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

func createHttpError(code, message string) *object.Struct {
	return &object.Struct{
		TypeName: "Error",
		Mutable: false,
		Fields: map[string]object.Object{
			"message": &object.String{Value: message},
			"code": &object.String{Value: code},
		},
	}
}

func newHttpResponse(fields map[string]object.Object) *object.Struct {
	return &object.Struct{
		TypeName: "HttpResponse",
		Mutable: false,
		Fields: fields,
	}
}
