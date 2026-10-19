package native_dns_preservation_test

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strconv"
	"testing"

	"google.golang.org/protobuf/proto"
)

// Unknown fields are decoded by the actual pinned Core, rather than a second
// schema model. Removing only the declared opaque fields must leave the full
// compiled protobuf unchanged. No Core instance or socket is created.
func TestOpaqueFieldsPreparation(t *testing.T) {
	var cases []struct {
		Name        string         `json:"name"`
		Config      map[string]any `json:"config"`
		OpaquePaths [][]string     `json:"opaquePaths"`
	}
	if err := json.Unmarshal(selectorFixture(t, "opaque-fields.json"), &cases); err != nil || len(cases) != 6 {
		t.Fatal("six opaque field profiles required", err)
	}
	count := 0
	for _, tc := range cases {
		count += len(tc.OpaquePaths)
		t.Run(tc.Name, func(t *testing.T) {
			source, err := json.Marshal(tc.Config)
			if err != nil {
				t.Fatal(err)
			}
			literal := opaqueClone(t, tc.Config)
			for _, path := range tc.OpaquePaths {
				if len(path) == 0 {
					t.Fatal("empty opaque field path")
				}
				parent, ok := opaqueValue(t, literal, literal, path[:len(path)-1], false).(map[string]any)
				if !ok {
					t.Fatal("opaque field parent must be an object")
				}
				key := path[len(path)-1]
				if _, present := parent[key]; !present {
					t.Fatal("declared opaque field is absent", path)
				}
				delete(parent, key)
			}
			actual, err := schemaFieldsBuild(source)
			if err != nil {
				t.Fatal("opaque source is not valid pinned Core configuration", err)
			}
			literalBytes, _ := json.Marshal(literal)
			want, err := schemaFieldsBuild(literalBytes)
			if err != nil || !proto.Equal(actual, want) {
				t.Fatal("declared opaque field changed compiled Core semantics", err)
			}
			if os.Getenv("NATIVE_DNS_PREPARER") != "" {
				check := func(t *testing.T) {
					effective := prepareEndpointAddress(t, source)
					for _, path := range tc.OpaquePaths {
						if !reflect.DeepEqual(opaqueValue(t, tc.Config, tc.Config, path, false),
							opaqueValue(t, effective, tc.Config, path, true)) {
							t.Fatal("native preparation changed opaque field", path)
						}
					}
					control := prepareEndpointAddress(t, literalBytes)
					effectiveBytes, _ := json.Marshal(effective)
					controlBytes, _ := json.Marshal(control)
					actual, err := schemaFieldsBuild(effectiveBytes)
					if err != nil {
						t.Fatal(err)
					}
					want, err := schemaFieldsBuild(controlBytes)
					if err != nil || !proto.Equal(actual, want) {
						t.Fatal("opaque field changed native-prepared typed semantics", err)
					}
				}
				t.Run("WindowsPreparer", check)
				if apple := os.Getenv("NATIVE_DNS_PREPARER_APPLE"); apple != "" {
					t.Run("ApplePreparer", func(t *testing.T) {
						t.Setenv("NATIVE_DNS_PREPARER", apple)
						check(t)
					})
				}
			}
			retained, err := json.Marshal(tc.Config)
			if err != nil || !bytes.Equal(retained, source) {
				t.Fatal("opaque source changed", err)
			}
			if tc.Name == "unknown_tls_and_transport_fields" {
				// The genuine TLSConfig member is not opaque: pinned Core rejects
				// the removed feature, unlike custom.allowInsecure in these cases.
				active := opaqueClone(t, tc.Config)
				tls := opaqueValue(t, active, active, []string{"outbounds", "0", "streamSettings", "tlsSettings"}, false).(map[string]any)
				tls["allowInsecure"] = true
				data, _ := json.Marshal(active)
				if _, err := schemaFieldsBuild(data); err == nil {
					t.Fatal("real TLS allowInsecure unexpectedly became metadata")
				}
			}
		})
	}
	if count != 18 {
		t.Fatal("eighteen opaque subtrees required")
	}
}

func opaqueClone(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func opaqueValue(t *testing.T, document, source map[string]any, path []string, prepared bool) any {
	t.Helper()
	var value any = document
	for depth, key := range path {
		switch node := value.(type) {
		case map[string]any:
			var present bool
			value, present = node[key]
			if !present {
				t.Fatal("missing exact opaque path key", path)
			}
		case []any:
			index, err := strconv.Atoi(key)
			if err != nil || index < 0 || index >= len(node) {
				t.Fatal("invalid opaque path array index", path)
			}
			if prepared && depth == 1 && (path[0] == "inbounds" || path[0] == "outbounds") {
				tag := source[path[0]].([]any)[index].(map[string]any)["tag"]
				value = nil
				for _, candidate := range node {
					if candidate.(map[string]any)["tag"] == tag {
						if value != nil {
							t.Fatal("ambiguous caller handler tag")
						}
						value = candidate
					}
				}
			} else if prepared && depth == 2 && path[0] == "routing" && path[1] == "rules" {
				caller := source["routing"].(map[string]any)["rules"].([]any)[index].(map[string]any)
				value = nil
				for _, candidate := range node {
					rule := candidate.(map[string]any)
					if reflect.DeepEqual(rule["domain"], caller["domain"]) && rule["outboundTag"] == caller["outboundTag"] {
						if value != nil {
							t.Fatal("ambiguous caller routing rule")
						}
						value = candidate
					}
				}
			} else {
				value = node[index]
			}
		default:
			t.Fatal("opaque path crossed a noncontainer", path)
		}
	}
	return value
}
