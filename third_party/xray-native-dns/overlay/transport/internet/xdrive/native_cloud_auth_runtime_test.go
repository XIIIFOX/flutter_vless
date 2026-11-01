package xdrive

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Independent request-side verifier. It does not call the production signer,
// s3Hash or s3HMAC, and is anchored by AWS's published GET Object vector:
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
func verifyNativeFixtureS3Signature(r *http.Request, body []byte, access, secret string) error {
	const algorithm = "AWS4-HMAC-SHA256"
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), algorithm+" ")
	if auth == r.Header.Get("Authorization") {
		return errors.New("wrong signature algorithm")
	}
	fields := map[string]string{}
	for _, entry := range strings.Split(auth, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || fields[key] != "" {
			return errors.New("invalid authorization fields")
		}
		fields[key] = value
	}
	scope := strings.Split(fields["Credential"], "/")
	stamp := r.Header.Get("X-Amz-Date")
	if len(scope) != 5 || scope[0] != access || scope[2] != "us-east-1" || scope[3] != "s3" || scope[4] != "aws4_request" || len(stamp) != 16 || scope[1] != stamp[:8] {
		return errors.New("wrong signing credential/scope/date")
	}
	payload := sha256.Sum256(body)
	payloadHex := hex.EncodeToString(payload[:])
	if r.Header.Get("X-Amz-Content-Sha256") != payloadHex {
		return errors.New("wire payload hash mismatch")
	}
	names := strings.Split(fields["SignedHeaders"], ";")
	if !sort.StringsAreSorted(names) {
		return errors.New("signed header order mismatch")
	}
	var canonicalHeaders strings.Builder
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || name != strings.ToLower(name) || seen[name] {
			return errors.New("invalid signed header list")
		}
		seen[name] = true
		value := r.Header.Get(name)
		if name == "host" {
			value = r.Host
		}
		fmt.Fprintf(&canonicalHeaders, "%s:%s\n", name, strings.Join(strings.Fields(value), " "))
	}
	if !seen["host"] || !seen["x-amz-date"] || r.Header.Get("X-Amz-Security-Token") != "" && !seen["x-amz-security-token"] {
		return errors.New("required signing header absent")
	}
	// S3 preserves the escaped object path, rather than normalizing dot/slash
	// segments. Query values are independently sorted and percent-encoded.
	query := strings.ReplaceAll(r.URL.Query().Encode(), "+", "%20")
	canonical := strings.Join([]string{r.Method, r.URL.EscapedPath(), query, canonicalHeaders.String(), fields["SignedHeaders"], payloadHex}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	toSign := strings.Join([]string{algorithm, stamp, strings.Join(scope[1:], "/"), hex.EncodeToString(digest[:])}, "\n")
	mac := func(key []byte, value string) []byte {
		h := hmac.New(sha256.New, key)
		_, _ = h.Write([]byte(value))
		return h.Sum(nil)
	}
	key := []byte("AWS4" + secret)
	for _, value := range scope[1:] {
		key = mac(key, value)
	}
	actual, err := hex.DecodeString(fields["Signature"])
	if err != nil || !hmac.Equal(actual, mac(key, toSign)) {
		return errors.New("request signature mismatch")
	}
	return nil
}

func TestAcceptanceXdriveS3SignatureVerifierVector(t *testing.T) {
	// Public, nonfunctional AWS documentation credentials; no account is used.
	const access = "AKIAIOSFODNN7EXAMPLE"
	const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	request, err := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Range", "bytes=0-9")
	request.Header.Set("X-Amz-Content-Sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	request.Header.Set("X-Amz-Date", "20130524T000000Z")
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+access+"/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")
	if err := verifyNativeFixtureS3Signature(request, nil, access, secret); err != nil {
		t.Fatal("AWS reference signature rejected", err)
	}
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Host = "wrong-host.invalid" },
		func(r *http.Request) { r.URL.Path = "/wrong-object" },
		func(r *http.Request) { r.URL.RawQuery = "unexpected=1" },
		func(r *http.Request) { r.Header.Set("Range", "bytes=1-9") },
		func(r *http.Request) { r.Method = "PUT" },
	} {
		mutated := request.Clone(context.Background())
		change(mutated)
		if verifyNativeFixtureS3Signature(mutated, nil, access, secret) == nil {
			t.Fatal("tampered request retained a valid signature")
		}
	}
	if verifyNativeFixtureS3Signature(request, []byte("tampered"), access, secret) == nil || verifyNativeFixtureS3Signature(request, nil, access, "wrong-secret") == nil {
		t.Fatal("payload or signing key tampering was accepted")
	}
}

func TestAcceptanceXdriveGoogleOAuthAndAPIHTTPAuthenticationAndCancellation(t *testing.T) {
	fake := newFakeDrive(t)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	const clientID, clientSecret, refresh = "fixture-client+/%", "fixture-secret&=", "fixture-refresh+/%"
	var phase atomic.Int32 // 0 stalls OAuth; 1 allows CRUD; 2 stalls API.
	var tokenRequests, apiRequests, rejected atomic.Int64
	started := []chan struct{}{make(chan struct{}), make(chan struct{})}
	drained := []chan struct{}{make(chan struct{}), make(chan struct{})}
	var startedOnce, drainedOnce [2]sync.Once
	forced := make(chan struct{})
	delegate := fake.server.Config.Handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stage := int(phase.Load())
		stall := -1
		if r.URL.Path == "/token" {
			tokenRequests.Add(1)
			if r.Method != "POST" || r.ParseForm() != nil || r.Form.Get("client_id") != clientID || r.Form.Get("client_secret") != clientSecret || r.Form.Get("refresh_token") != refresh || r.Form.Get("grant_type") != "refresh_token" {
				rejected.Add(1)
				http.Error(w, "bad fixture OAuth form", http.StatusUnauthorized)
				return
			}
			if stage == 0 {
				stall = 0
			}
		} else {
			apiRequests.Add(1)
			if r.Header.Get("Authorization") != "Bearer fake-token" {
				rejected.Add(1)
				http.Error(w, "bad fixture bearer token", http.StatusUnauthorized)
				return
			}
			if stage == 2 {
				stall = 1
			}
		}
		if stall >= 0 {
			startedOnce[stall].Do(func() { close(started[stall]) })
			defer drainedOnce[stall].Do(func() { close(drained[stall]) })
			select {
			case <-r.Context().Done():
			case <-forced:
			}
			return
		}
		delegate.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { close(forced); server.CloseClientConnections(); server.Close() })
	// newFakeDrive already owns restoration of these globals. Only numeric
	// loopback endpoints are substituted; the real Core HTTP client is used.
	driveTokenURL, driveFilesURL, driveUploadURL = server.URL+"/token", server.URL+"/files", server.URL+"/upload"
	stream := nativeS3Stream()
	stream.ProtocolSettings = &Config{Service: "google-drive", RemoteFolder: "synthetic-folder", Secrets: []string{clientID, clientSecret, refresh}}
	for stage := 0; stage < 2; stage++ {
		ctx, owner := ContextWithNativeLifetime(parent)
		defer owner.Close()
		base, err := newNativeStorage(ctx, stream)
		if err != nil {
			t.Fatal(err)
		}
		storage := sessionStorage(base)
		defer storage.Close()
		if stage == 1 {
			phase.Store(1)
			if err := storage.Put(ctx, "proof/payload", []byte("authenticated-drive-payload")); err != nil {
				t.Fatal(err)
			}
			body, err := storage.Get(ctx, "proof/payload")
			if err != nil || string(body) != "authenticated-drive-payload" {
				t.Fatal("authenticated Drive round trip failed", err)
			}
			phase.Store(2)
		}
		result := make(chan error, 1)
		go func() { _, err := storage.Get(context.Background(), "proof/payload"); result <- err }()
		select {
		case <-started[stage]:
		case <-time.After(2 * time.Second):
			t.Fatal("owned Google HTTP request did not reach the expected stage", stage)
		}
		until := time.Now().Add(2 * time.Second)
		owner.Close()
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("cancelled Google request succeeded", stage)
			}
		case <-time.After(time.Until(until)):
			t.Fatal("Google operation survived its service owner", stage)
		}
		select {
		case <-drained[stage]:
		case <-time.After(time.Until(until)):
			t.Fatal("Google HTTP handler did not observe socket cancellation", stage)
		}
		if owner.ResourceCount() != 0 || parent.Err() != nil || !time.Now().Before(until) {
			t.Fatal("Google cancellation retained resources, cancelled parent or exceeded deadline", stage)
		}
	}
	if tokenRequests.Load() != 2 || apiRequests.Load() == 0 || rejected.Load() != 0 {
		t.Fatalf("Google authentication/cache request ledger mismatch: OAuth=%d API=%d rejected=%d", tokenRequests.Load(), apiRequests.Load(), rejected.Load())
	}
}
