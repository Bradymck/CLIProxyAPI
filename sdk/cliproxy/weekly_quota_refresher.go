package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// Upstream usage endpoints, matching what the management center quota page
// queries per credential.
const (
	claudeOAuthUsageURL = "https://api.anthropic.com/api/oauth/usage"
	codexWhamUsageURL   = "https://chatgpt.com/backend-api/wham/usage"

	claudeUsageUserAgent = "claude-cli/2.1.321 (external, cli)"
	claudeOAuthBeta      = "oauth-2025-04-20"
	codexUsageUserAgent  = "codex-tui/0.154.0 (Mac OS 26.5.2; arm64) iTerm.app/3.6.11 (codex-tui; 0.154.0)"

	weeklyQuotaRefreshInterval = 10 * time.Minute
	weeklyQuotaCheckInterval   = 30 * time.Second
	weeklyQuotaStartupDelay    = 15 * time.Second
	weeklyQuotaFetchSpacing    = 2 * time.Second
	weeklyQuotaFetchTimeout    = 20 * time.Second
	weeklyQuotaMaxBodyBytes    = 1 << 20
)

// weeklyQuotaRefresher actively fetches each Claude/Codex OAuth credential's
// weekly window reset while reset-first routing is active, so the selector can
// rank credentials that have not served traffic yet. It is best-effort: every
// failure is logged at debug level and retried on the next interval.
type weeklyQuotaRefresher struct {
	manager *coreauth.Manager
	config  func() *config.Config

	interval      time.Duration
	checkInterval time.Duration
	startupDelay  time.Duration
	spacing       time.Duration

	claudeURL string
	codexURL  string
	// httpClient builds the client for one credential; defaults to the
	// executor proxy conventions (request override, auth proxy, global proxy).
	httpClient func(ctx context.Context, auth *coreauth.Auth) *http.Client
	now        func() time.Time

	// lastAttempt is only touched by the run goroutine.
	lastAttempt map[string]time.Time
}

func newWeeklyQuotaRefresher(manager *coreauth.Manager, cfg func() *config.Config) *weeklyQuotaRefresher {
	r := &weeklyQuotaRefresher{
		manager:       manager,
		config:        cfg,
		interval:      weeklyQuotaRefreshInterval,
		checkInterval: weeklyQuotaCheckInterval,
		startupDelay:  weeklyQuotaStartupDelay,
		spacing:       weeklyQuotaFetchSpacing,
		claudeURL:     claudeOAuthUsageURL,
		codexURL:      codexWhamUsageURL,
		now:           time.Now,
		lastAttempt:   make(map[string]time.Time),
	}
	r.httpClient = func(ctx context.Context, auth *coreauth.Auth) *http.Client {
		var c *config.Config
		if r.config != nil {
			c = r.config()
		}
		return helps.NewProxyAwareHTTPClient(ctx, c, auth, weeklyQuotaFetchTimeout)
	}
	return r
}

// run blocks until ctx is cancelled. New credentials are picked up on the next
// check tick because they have no recorded attempt.
func (r *weeklyQuotaRefresher) run(ctx context.Context) {
	if r == nil || r.manager == nil {
		return
	}
	if !sleepContext(ctx, r.startupDelay) {
		return
	}
	ticker := time.NewTicker(r.checkInterval)
	defer ticker.Stop()
	for {
		r.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick refreshes every eligible credential whose last attempt is older than
// the refresh interval, sequentially with a small gap between requests.
func (r *weeklyQuotaRefresher) tick(ctx context.Context) {
	if ctx.Err() != nil || !r.manager.ResetFirstRoutingActive() {
		return
	}
	auths := r.manager.List()
	seen := make(map[string]struct{}, len(auths))
	fetched := 0
	for _, auth := range auths {
		if auth == nil || !weeklyQuotaRefreshEligible(auth) {
			continue
		}
		seen[auth.ID] = struct{}{}
		if last, ok := r.lastAttempt[auth.ID]; ok && r.now().Sub(last) < r.interval {
			continue
		}
		if fetched > 0 && !sleepContext(ctx, r.spacing) {
			return
		}
		fetched++
		r.lastAttempt[auth.ID] = r.now()
		r.refreshOne(ctx, auth)
		if ctx.Err() != nil {
			return
		}
	}
	for id := range r.lastAttempt {
		if _, ok := seen[id]; !ok {
			delete(r.lastAttempt, id)
		}
	}
}

func (r *weeklyQuotaRefresher) refreshOne(ctx context.Context, auth *coreauth.Auth) {
	resetAt, errFetch := r.fetchWeeklyReset(ctx, auth)
	if errFetch != nil {
		if ctx.Err() == nil {
			log.WithError(errFetch).Debugf("weekly quota refresh failed for %s auth %s", auth.Provider, auth.ID)
		}
		return
	}
	if !resetAt.After(r.now()) {
		log.Debugf("weekly quota refresh for %s auth %s returned no future reset", auth.Provider, auth.ID)
		return
	}
	if r.manager.ApplyWeeklyQuotaReset(auth.ID, resetAt, r.now()) {
		log.Debugf("weekly quota reset for %s auth %s set to %s", auth.Provider, auth.ID, resetAt.UTC().Format(time.RFC3339))
	}
}

// weeklyQuotaRefreshEligible limits active probes to enabled Claude/Codex OAuth
// credentials that carry an access token.
func weeklyQuotaRefreshEligible(auth *coreauth.Auth) bool {
	if auth == nil || auth.Disabled || auth.Status == coreauth.StatusDisabled {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude", "codex":
	default:
		return false
	}
	if auth.AuthKind() == coreauth.AuthKindAPIKey {
		return false
	}
	return oauthAccessToken(auth) != ""
}

func oauthAccessToken(auth *coreauth.Auth) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	for _, key := range []string{"access_token", "accessToken"} {
		if v, ok := auth.Metadata[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (r *weeklyQuotaRefresher) fetchWeeklyReset(ctx context.Context, auth *coreauth.Auth) (time.Time, error) {
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	token := oauthAccessToken(auth)
	if token == "" {
		return time.Time{}, fmt.Errorf("missing access token")
	}
	var url string
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("Accept", "application/json")
	switch provider {
	case "claude":
		url = r.claudeURL
		header.Set("User-Agent", claudeUsageUserAgent)
		header.Set("Anthropic-Beta", claudeOAuthBeta)
	case "codex":
		url = r.codexURL
		header.Set("User-Agent", codexUsageUserAgent)
		if accountID, ok := auth.Metadata["account_id"].(string); ok && strings.TrimSpace(accountID) != "" {
			header.Set("Chatgpt-Account-Id", strings.TrimSpace(accountID))
		}
	default:
		return time.Time{}, fmt.Errorf("unsupported provider %q", provider)
	}

	reqCtx, cancel := context.WithTimeout(ctx, weeklyQuotaFetchTimeout)
	defer cancel()
	req, errReq := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if errReq != nil {
		return time.Time{}, errReq
	}
	req.Header = header
	client := r.httpClient(reqCtx, auth)
	if client == nil {
		client = &http.Client{Timeout: weeklyQuotaFetchTimeout}
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return time.Time{}, errDo
	}
	defer func() { _ = resp.Body.Close() }()
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, weeklyQuotaMaxBodyBytes))
	if errRead != nil {
		return time.Time{}, errRead
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return time.Time{}, fmt.Errorf("usage endpoint returned status %d", resp.StatusCode)
	}
	if provider == "claude" {
		return parseClaudeWeeklyReset(body)
	}
	return parseCodexWeeklyReset(body, r.now())
}

// parseClaudeWeeklyReset reads seven_day.resets_at from the OAuth usage payload.
func parseClaudeWeeklyReset(body []byte) (time.Time, error) {
	var payload struct {
		SevenDay *struct {
			ResetsAt json.RawMessage `json:"resets_at"`
		} `json:"seven_day"`
	}
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return time.Time{}, fmt.Errorf("decode claude usage: %w", errUnmarshal)
	}
	if payload.SevenDay == nil {
		return time.Time{}, fmt.Errorf("claude usage has no seven_day window")
	}
	resetAt, ok := parseResetInstant(payload.SevenDay.ResetsAt)
	if !ok {
		return time.Time{}, fmt.Errorf("claude usage seven_day has no resets_at")
	}
	return resetAt, nil
}

// parseCodexWeeklyReset reads rate_limit.secondary_window (the weekly window,
// the same one reported by X-Codex-Secondary-* headers).
func parseCodexWeeklyReset(body []byte, now time.Time) (time.Time, error) {
	type window struct {
		ResetAt           json.RawMessage `json:"reset_at"`
		ResetAtCamel      json.RawMessage `json:"resetAt"`
		ResetAfterSeconds json.RawMessage `json:"reset_after_seconds"`
		ResetAfterCamel   json.RawMessage `json:"resetAfterSeconds"`
	}
	type rateLimit struct {
		Secondary      *window `json:"secondary_window"`
		SecondaryCamel *window `json:"secondaryWindow"`
	}
	var payload struct {
		RateLimit      *rateLimit `json:"rate_limit"`
		RateLimitCamel *rateLimit `json:"rateLimit"`
	}
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return time.Time{}, fmt.Errorf("decode codex usage: %w", errUnmarshal)
	}
	rl := payload.RateLimit
	if rl == nil {
		rl = payload.RateLimitCamel
	}
	if rl == nil {
		return time.Time{}, fmt.Errorf("codex usage has no rate_limit")
	}
	w := rl.Secondary
	if w == nil {
		w = rl.SecondaryCamel
	}
	if w == nil {
		return time.Time{}, fmt.Errorf("codex usage has no secondary_window")
	}
	for _, raw := range []json.RawMessage{w.ResetAt, w.ResetAtCamel} {
		if t, ok := parseResetInstant(raw); ok {
			return t, nil
		}
	}
	for _, raw := range []json.RawMessage{w.ResetAfterSeconds, w.ResetAfterCamel} {
		if secs, ok := parseJSONNumber(raw); ok && secs >= 0 {
			return now.Add(time.Duration(secs * float64(time.Second))), nil
		}
	}
	return time.Time{}, fmt.Errorf("codex usage secondary_window has no reset")
}

// parseResetInstant accepts an RFC3339 string or unix seconds/milliseconds as
// a JSON number or numeric string.
func parseResetInstant(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return time.Time{}, false
	}
	var text string
	if errString := json.Unmarshal(raw, &text); errString == nil {
		text = strings.TrimSpace(text)
		if text == "" {
			return time.Time{}, false
		}
		if t, errParse := time.Parse(time.RFC3339Nano, text); errParse == nil {
			return t, true
		}
	}
	value, ok := parseJSONNumber(raw)
	if !ok || value <= 0 {
		return time.Time{}, false
	}
	if value > 1e12 {
		value /= 1000
	}
	return time.Unix(int64(value), 0), true
}

func parseJSONNumber(raw json.RawMessage) (float64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var number float64
	if errNumber := json.Unmarshal(raw, &number); errNumber == nil {
		return number, true
	}
	var text string
	if errString := json.Unmarshal(raw, &text); errString == nil {
		if value, errParse := strconv.ParseFloat(strings.TrimSpace(text), 64); errParse == nil {
			return value, true
		}
	}
	return 0, false
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
