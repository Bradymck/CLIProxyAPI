package cliproxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type usageServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests map[string][]http.Header
}

func newUsageServer(t *testing.T, claudeReset time.Time, codexReset time.Time) *usageServer {
	t.Helper()
	s := &usageServer{requests: make(map[string][]http.Header)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests[r.URL.Path] = append(s.requests[r.URL.Path], r.Header.Clone())
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/claude":
			_, _ = fmt.Fprintf(w, `{"five_hour":{"utilization":12,"resets_at":"2000-01-01T00:00:00Z"},"seven_day":{"utilization":40,"resets_at":%q}}`,
				claudeReset.UTC().Format(time.RFC3339))
		case "/codex":
			_, _ = fmt.Fprintf(w, `{"plan_type":"pro","rate_limit":{"primary_window":{"reset_at":1},"secondary_window":{"used_percent":20,"limit_window_seconds":604800,"reset_at":%d}}}`,
				codexReset.Unix())
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *usageServer) count(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests[path])
}

func (s *usageServer) firstHeader(path string) http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.requests[path]) == 0 {
		return nil
	}
	return s.requests[path][0]
}

func newTestRefresher(t *testing.T, selector coreauth.Selector, srv *usageServer) (*weeklyQuotaRefresher, *coreauth.Manager) {
	t.Helper()
	manager := coreauth.NewManager(nil, selector, nil)
	ctx := context.Background()
	auths := []*coreauth.Auth{
		{ID: "claude-oauth", Provider: "claude", Metadata: map[string]any{"type": "claude", "access_token": "claude-token"}},
		{ID: "codex-oauth", Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": "codex-token", "account_id": "acct-1"}},
		{ID: "claude-apikey", Provider: "claude", Attributes: map[string]string{"api_key": "sk-ant"}},
		{ID: "claude-disabled", Provider: "claude", Disabled: true, Status: coreauth.StatusDisabled, Metadata: map[string]any{"access_token": "x"}},
		{ID: "gemini-oauth", Provider: "gemini", Metadata: map[string]any{"access_token": "g"}},
	}
	for _, a := range auths {
		if _, err := manager.Register(ctx, a); err != nil {
			t.Fatalf("Register(%s) error = %v", a.ID, err)
		}
	}
	r := newWeeklyQuotaRefresher(manager, nil)
	r.claudeURL = srv.URL + "/claude"
	r.codexURL = srv.URL + "/codex"
	r.httpClient = func(context.Context, *coreauth.Auth) *http.Client { return srv.Client() }
	r.startupDelay = 0
	r.spacing = 0
	return r, manager
}

func TestWeeklyQuotaRefresher_WritesResetsForOAuthAuths(t *testing.T) {
	now := time.Now()
	claudeReset := now.Add(40 * time.Hour).Truncate(time.Second)
	codexReset := now.Add(90 * time.Hour).Truncate(time.Second)
	srv := newUsageServer(t, claudeReset, codexReset)
	r, manager := newTestRefresher(t, &coreauth.ResetFirstSelector{}, srv)

	r.tick(context.Background())

	if got := srv.count("/claude"); got != 1 {
		t.Fatalf("claude usage requests = %d, want 1 (api-key and disabled auths skipped)", got)
	}
	if got := srv.count("/codex"); got != 1 {
		t.Fatalf("codex usage requests = %d, want 1", got)
	}
	ch := srv.firstHeader("/claude")
	if ch.Get("Authorization") != "Bearer claude-token" || ch.Get("Anthropic-Beta") != claudeOAuthBeta {
		t.Fatalf("claude headers = %v", ch)
	}
	xh := srv.firstHeader("/codex")
	if xh.Get("Authorization") != "Bearer codex-token" || xh.Get("Chatgpt-Account-Id") != "acct-1" {
		t.Fatalf("codex headers = %v", xh)
	}

	for id, want := range map[string]time.Time{"claude-oauth": claudeReset, "codex-oauth": codexReset} {
		auth, ok := manager.GetByID(id)
		if !ok {
			t.Fatalf("GetByID(%s) missing", id)
		}
		got, known := coreauth.WeeklyQuotaResetAt(auth, time.Now())
		if !known || !got.Equal(want) {
			t.Fatalf("%s WeeklyQuotaResetAt = %v,%v want %v", id, got, known, want)
		}
		if auth.Quota.ObservedAt.IsZero() {
			t.Fatalf("%s ObservedAt not set", id)
		}
	}

	// Within the refresh interval nothing is re-fetched.
	r.tick(context.Background())
	if srv.count("/claude") != 1 || srv.count("/codex") != 1 {
		t.Fatalf("re-fetched within interval: claude=%d codex=%d", srv.count("/claude"), srv.count("/codex"))
	}
	// After the interval each credential is fetched again.
	r.now = func() time.Time { return time.Now().Add(r.interval + time.Second) }
	r.tick(context.Background())
	if srv.count("/claude") != 2 || srv.count("/codex") != 2 {
		t.Fatalf("not re-fetched after interval: claude=%d codex=%d", srv.count("/claude"), srv.count("/codex"))
	}
}

func TestWeeklyQuotaRefresher_IdleWithoutResetFirst(t *testing.T) {
	srv := newUsageServer(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	r, _ := newTestRefresher(t, &coreauth.RoundRobinSelector{}, srv)
	r.tick(context.Background())
	if srv.count("/claude")+srv.count("/codex") != 0 {
		t.Fatal("refresher fetched usage while reset-first routing is inactive")
	}
}

func TestWeeklyQuotaRefresher_UpstreamErrorLeavesAuthUnknown(t *testing.T) {
	srv := newUsageServer(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	r, manager := newTestRefresher(t, &coreauth.ResetFirstSelector{}, srv)
	r.claudeURL = srv.URL + "/unauthorized"
	r.tick(context.Background())
	auth, _ := manager.GetByID("claude-oauth")
	if _, known := coreauth.WeeklyQuotaResetAt(auth, time.Now()); known {
		t.Fatal("failed fetch should not record a reset")
	}
}

func TestWeeklyQuotaRefresher_RunStopsOnCancel(t *testing.T) {
	srv := newUsageServer(t, time.Now().Add(time.Hour), time.Now().Add(time.Hour))
	r, _ := newTestRefresher(t, &coreauth.ResetFirstSelector{}, srv)
	r.startupDelay = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("run did not return after cancellation")
	}
}

func TestParseWeeklyResetPayloads(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	want := time.Unix(1_800_100_000, 0)

	claudeCases := map[string]string{
		"rfc3339":     `{"seven_day":{"resets_at":"` + want.UTC().Format(time.RFC3339) + `"}}`,
		"fractional":  `{"seven_day":{"resets_at":"` + want.UTC().Format("2006-01-02T15:04:05.000000Z07:00") + `"}}`,
		"unix number": `{"seven_day":{"resets_at":1800100000}}`,
	}
	for name, body := range claudeCases {
		got, err := parseClaudeWeeklyReset([]byte(body))
		if err != nil || !got.Equal(want) {
			t.Errorf("claude %s: got %v err %v", name, got, err)
		}
	}
	for name, body := range map[string]string{
		"no window": `{"five_hour":{"resets_at":"2030-01-01T00:00:00Z"}}`,
		"null":      `{"seven_day":{"resets_at":null}}`,
		"garbage":   `not json`,
	} {
		if _, err := parseClaudeWeeklyReset([]byte(body)); err == nil {
			t.Errorf("claude %s: expected error", name)
		}
	}

	codexCases := map[string]string{
		"reset_at":            `{"rate_limit":{"secondary_window":{"reset_at":1800100000}}}`,
		"reset_at ms string":  `{"rate_limit":{"secondary_window":{"reset_at":"1800100000000"}}}`,
		"camel":               `{"rateLimit":{"secondaryWindow":{"resetAt":1800100000}}}`,
		"reset_after_seconds": `{"rate_limit":{"secondary_window":{"reset_after_seconds":100000}}}`,
	}
	for name, body := range codexCases {
		got, err := parseCodexWeeklyReset([]byte(body), now)
		if err != nil || !got.Equal(want) {
			t.Errorf("codex %s: got %v err %v", name, got, err)
		}
	}
	for name, body := range map[string]string{
		"no rate_limit": `{"plan_type":"free"}`,
		"no secondary":  `{"rate_limit":{"primary_window":{"reset_at":1800100000}}}`,
		"empty window":  `{"rate_limit":{"secondary_window":{}}}`,
	} {
		if _, err := parseCodexWeeklyReset([]byte(body), now); err == nil {
			t.Errorf("codex %s: expected error", name)
		}
	}
}
