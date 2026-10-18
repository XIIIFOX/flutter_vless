package XRay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xtls/xray-core/infra/conf/serial"
)

func TestCompatibilityJSONCorpus(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "tool", "fixtures", "compatibility", "json.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name       string `json:"name"`
		Input      string `json:"input"`
		CoreDecode bool   `json:"coreDecode"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			_, err := serial.DecodeJSONConfig(strings.NewReader(tc.Input))
			if (err == nil) != tc.CoreDecode {
				t.Fatalf("Pinned Core decode outcome differs: accepted=%v", err == nil)
			}
		})
	}
}
