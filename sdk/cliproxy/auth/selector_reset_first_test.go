package auth

import (
	"context"
	"strconv"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func claudeAuthResettingIn(id string, in time.Duration) *Auth {
	return &Auth{
		ID:       id,
		Provider: "claude",
		Quota: QuotaState{
			ObservedAt: time.Now(),
			Signals: map[string]string{
				"Anthropic-Ratelimit-Unified-7d-Reset": strconv.FormatInt(time.Now().Add(in).Unix(), 10),
			},
		},
	}
}

func TestResetFirstSelectorPick_PrefersSoonestWeeklyReset(t *testing.T) {
	t.Parallel()

	selector := &ResetFirstSelector{}
	auths := []*Auth{
		claudeAuthResettingIn("a-four-days", 96*time.Hour),
		claudeAuthResettingIn("b-tomorrow", 20*time.Hour),
		claudeAuthResettingIn("c-three-days", 72*time.Hour),
	}
	for i := 0; i < 3; i++ {
		got, err := selector.Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
		if err != nil {
			t.Fatalf("Pick() error = %v", err)
		}
		if got == nil || got.ID != "b-tomorrow" {
			t.Fatalf("Pick() = %v, want b-tomorrow", got)
		}
	}
}

func TestResetFirstSelectorPick_ProbesUnknownFirst(t *testing.T) {
	t.Parallel()

	stale := claudeAuthResettingIn("z-stale", -time.Hour) // window already rolled over
	auths := []*Auth{
		claudeAuthResettingIn("a-tomorrow", 20*time.Hour),
		stale,
	}
	got, err := (&ResetFirstSelector{}).Pick(context.Background(), "claude", "", cliproxyexecutor.Options{}, auths)
	if err != nil {
		t.Fatalf("Pick() error = %v", err)
	}
	if got == nil || got.ID != "z-stale" {
		t.Fatalf("Pick() = %v, want z-stale (unknown reset is probed first)", got)
	}
}

func TestWeeklyQuotaResetAt_CodexSecondaryWindow(t *testing.T) {
	t.Parallel()

	now := time.Now()
	resetAt := now.Add(50 * time.Hour).Truncate(time.Second)
	byAt := &Auth{Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Secondary-Reset-At": strconv.FormatInt(resetAt.Unix(), 10),
	}}}
	if got, ok := WeeklyQuotaResetAt(byAt, now); !ok || !got.Equal(resetAt) {
		t.Fatalf("reset-at = %v,%v want %v", got, ok, resetAt)
	}
	byAfter := &Auth{Provider: "codex", Quota: QuotaState{ObservedAt: now, Signals: map[string]string{
		"X-Codex-Secondary-Reset-After-Seconds": "3600",
	}}}
	if got, ok := WeeklyQuotaResetAt(byAfter, now); !ok || !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("reset-after = %v,%v want %v", got, ok, now.Add(time.Hour))
	}
	if _, ok := WeeklyQuotaResetAt(&Auth{Provider: "codex"}, now); ok {
		t.Fatalf("auth without signals must be unknown")
	}
}

func TestSchedulerPick_ResetFirstFollowsQuotaUpdates(t *testing.T) {
	t.Parallel()

	scheduler := newSchedulerForTest(
		&ResetFirstSelector{},
		claudeAuthResettingIn("a", 96*time.Hour),
		claudeAuthResettingIn("b", 20*time.Hour),
		claudeAuthResettingIn("c", 72*time.Hour),
	)
	got, errPick := scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil || got == nil || got.ID != "b" {
		t.Fatalf("pickSingle() = %v, %v; want b", got, errPick)
	}

	// "c" gets a fresher observation showing it resets even sooner.
	updated := claudeAuthResettingIn("c", 2*time.Hour)
	updated.Generation = 1
	updated.UpdatedAt = time.Now()
	scheduler.upsertAuth(updated)
	got, errPick = scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, nil)
	if errPick != nil || got == nil || got.ID != "c" {
		t.Fatalf("pickSingle() after update = %v, %v; want c", got, errPick)
	}

	// Excluding "c" (e.g. it just failed with a 5h limit) falls back to the next soonest.
	got, errPick = scheduler.pickSingle(context.Background(), "claude", "", cliproxyexecutor.Options{}, map[string]struct{}{"c": {}})
	if errPick != nil || got == nil || got.ID != "b" {
		t.Fatalf("pickSingle() excluding c = %v, %v; want b", got, errPick)
	}
}

func TestSchedulerPick_ResetFirstMixedProviders(t *testing.T) {
	t.Parallel()

	codexSoon := &Auth{ID: "codex-soon", Provider: "codex", Quota: QuotaState{ObservedAt: time.Now(), Signals: map[string]string{
		"X-Codex-Secondary-Reset-At": strconv.FormatInt(time.Now().Add(5*time.Hour).Unix(), 10),
	}}}
	scheduler := newSchedulerForTest(
		&ResetFirstSelector{},
		claudeAuthResettingIn("claude-later", 90*time.Hour),
		codexSoon,
	)
	got, provider, errPick := scheduler.pickMixed(context.Background(), []string{"claude", "codex"}, "", cliproxyexecutor.Options{}, nil)
	if errPick != nil || got == nil || got.ID != "codex-soon" || provider != "codex" {
		t.Fatalf("pickMixed() = %v, %q, %v; want codex-soon/codex", got, provider, errPick)
	}
}
