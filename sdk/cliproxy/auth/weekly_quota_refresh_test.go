package auth

import (
	"context"
	"strconv"
	"testing"
	"time"
)

func TestApplyWeeklyResetSignal_ClaudeKeepsPassiveSignals(t *testing.T) {
	t.Parallel()

	observed := time.Now().Add(-time.Minute).Truncate(time.Second)
	q := QuotaState{
		ObservedAt: observed,
		Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-Status":   "rejected",
			"Anthropic-Ratelimit-Unified-7d-Reset": "1",
		},
	}
	resetAt := time.Now().Add(50 * time.Hour).Truncate(time.Second)
	if !applyWeeklyResetSignal(&q, "claude", resetAt, time.Now()) {
		t.Fatal("applyWeeklyResetSignal() = false, want true")
	}
	if got := q.Signals["Anthropic-Ratelimit-Unified-Status"]; got != "rejected" {
		t.Fatalf("status signal = %q, want rejected preserved", got)
	}
	if !q.ObservedAt.Equal(observed) {
		t.Fatalf("ObservedAt = %v, want passive %v kept", q.ObservedAt, observed)
	}
	got, ok := weeklyResetFromQuota(q, time.Now())
	if !ok || !got.Equal(resetAt) {
		t.Fatalf("weeklyResetFromQuota() = %v,%v want %v", got, ok, resetAt)
	}
	if applyWeeklyResetSignal(&q, "claude", resetAt, time.Now()) {
		t.Fatal("second identical apply reported a change")
	}
}

func TestApplyWeeklyResetSignal_CodexDropsRelativeReset(t *testing.T) {
	t.Parallel()

	q := QuotaState{Signals: map[string]string{"x-codex-secondary-reset-after-seconds": "10"}}
	now := time.Now()
	resetAt := now.Add(30 * time.Hour).Truncate(time.Second)
	if !applyWeeklyResetSignal(&q, "codex", resetAt, now) {
		t.Fatal("applyWeeklyResetSignal() = false, want true")
	}
	if _, exists := q.Signals["x-codex-secondary-reset-after-seconds"]; exists {
		t.Fatal("relative reset signal was not dropped")
	}
	if q.Signals["X-Codex-Secondary-Reset-At"] != strconv.FormatInt(resetAt.Unix(), 10) {
		t.Fatalf("reset-at signal = %q", q.Signals["X-Codex-Secondary-Reset-At"])
	}
	if !q.ObservedAt.Equal(now) {
		t.Fatalf("ObservedAt = %v, want %v when previously empty", q.ObservedAt, now)
	}
}

func TestApplyWeeklyResetSignal_UnsupportedProvider(t *testing.T) {
	t.Parallel()

	q := QuotaState{}
	if applyWeeklyResetSignal(&q, "gemini", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("unsupported provider should not be written")
	}
	if q.Signals != nil {
		t.Fatal("signals should stay nil")
	}
}

func TestManagerApplyWeeklyQuotaReset_RanksUnseenAuth(t *testing.T) {
	t.Parallel()

	m := NewManager(nil, &ResetFirstSelector{}, nil)
	ctx := context.Background()
	for _, id := range []string{"fresh", "observed"} {
		if _, err := m.Register(ctx, &Auth{ID: id, Provider: "claude"}); err != nil {
			t.Fatalf("Register(%s) error = %v", id, err)
		}
	}
	now := time.Now()
	if !m.ApplyWeeklyQuotaReset("observed", now.Add(80*time.Hour), now) {
		t.Fatal("ApplyWeeklyQuotaReset(observed) = false")
	}
	if !m.ApplyWeeklyQuotaReset("fresh", now.Add(10*time.Hour), now) {
		t.Fatal("ApplyWeeklyQuotaReset(fresh) = false")
	}
	if m.ApplyWeeklyQuotaReset("missing", now.Add(time.Hour), now) {
		t.Fatal("ApplyWeeklyQuotaReset(missing) = true")
	}

	fresh, _ := m.GetByID("fresh")
	observed, _ := m.GetByID("observed")
	if got := pickEarliestWeeklyReset([]*Auth{observed, fresh}, now); got == nil || got.ID != "fresh" {
		t.Fatalf("pickEarliestWeeklyReset() = %v, want fresh", got)
	}

	// The scheduler snapshot used by reset-first picks sees the new reset too.
	m.scheduler.mu.Lock()
	var scheduled *Auth
	if providerState := m.scheduler.providers["claude"]; providerState != nil {
		if meta := providerState.auths["fresh"]; meta != nil {
			scheduled = meta.auth
		}
	}
	m.scheduler.mu.Unlock()
	if got, ok := WeeklyQuotaResetAt(scheduled, now); !ok || got.Unix() != now.Add(10*time.Hour).Unix() {
		t.Fatalf("scheduler WeeklyQuotaResetAt = %v,%v", got, ok)
	}
}

func TestSelectorUsesResetFirst(t *testing.T) {
	t.Parallel()

	affinity := NewSessionAffinitySelector(&ResetFirstSelector{})
	defer affinity.Stop()
	otherAffinity := NewSessionAffinitySelector(&RoundRobinSelector{})
	defer otherAffinity.Stop()

	cases := []struct {
		name string
		sel  Selector
		want bool
	}{
		{"reset-first", &ResetFirstSelector{}, true},
		{"affinity over reset-first", affinity, true},
		{"round-robin", &RoundRobinSelector{}, false},
		{"affinity over round-robin", otherAffinity, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := selectorUsesResetFirst(tc.sel); got != tc.want {
			t.Errorf("%s: selectorUsesResetFirst() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
