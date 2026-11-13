package auth

import (
	"context"
	"strconv"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// ResetFirstSelector prefers the credential whose weekly (7-day) quota window
// resets soonest, so quota that is about to expire is burned before quota that
// still has days left. Credentials without an observed future reset time are
// tried first so their window gets observed; ties keep deterministic ordering.
// Credentials in cooldown (for example after hitting the 5-hour limit) are
// already excluded from the candidate set, so the next-soonest credential is
// used automatically.
type ResetFirstSelector struct{}

// Pick selects the available auth with the soonest weekly quota reset.
func (s *ResetFirstSelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	_ = opts
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	return pickEarliestWeeklyReset(available, now), nil
}

// pickEarliestWeeklyReset returns the auth that should be drained first.
func pickEarliestWeeklyReset(auths []*Auth, now time.Time) *Auth {
	var best *Auth
	var bestKey resetRank
	for _, candidate := range auths {
		if candidate == nil {
			continue
		}
		key := weeklyResetRank(candidate, now)
		if best == nil || key.less(bestKey) {
			best, bestKey = candidate, key
		}
	}
	return best
}

// resetRank orders credentials: unknown reset first, then earliest reset.
type resetRank struct {
	known   bool
	resetAt time.Time
}

func (r resetRank) less(other resetRank) bool {
	if r.known != other.known {
		return !r.known
	}
	return r.resetAt.Before(other.resetAt)
}

func weeklyResetRank(auth *Auth, now time.Time) resetRank {
	resetAt, ok := WeeklyQuotaResetAt(auth, now)
	return resetRank{known: ok, resetAt: resetAt}
}

// WeeklyQuotaResetAt returns the next weekly quota reset observed for auth.
// It reads the passive quota snapshot captured from upstream response headers
// (Claude unified 7d window, Codex secondary window). Reset times that are
// already in the past are treated as unknown because the window has rolled.
func WeeklyQuotaResetAt(auth *Auth, now time.Time) (time.Time, bool) {
	if auth == nil {
		return time.Time{}, false
	}
	best, found := weeklyResetFromQuota(auth.Quota, now)
	for _, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		if t, ok := weeklyResetFromQuota(state.Quota, now); ok && (!found || state.Quota.ObservedAt.After(auth.Quota.ObservedAt)) {
			best, found = t, true
		}
	}
	return best, found
}

func weeklyResetFromQuota(q QuotaState, now time.Time) (time.Time, bool) {
	if len(q.Signals) == 0 {
		return time.Time{}, false
	}
	lookup := func(name string) string {
		for key, value := range q.Signals {
			if strings.EqualFold(key, name) {
				return strings.TrimSpace(value)
			}
		}
		return ""
	}
	var resetAt time.Time
	if raw := lookup("Anthropic-Ratelimit-Unified-7d-Reset"); raw != "" {
		resetAt = parseUnixSeconds(raw)
	} else if raw := lookup("X-Codex-Secondary-Reset-At"); raw != "" {
		resetAt = parseUnixSeconds(raw)
	} else if raw := lookup("X-Codex-Secondary-Reset-After-Seconds"); raw != "" && !q.ObservedAt.IsZero() {
		if secs, errParse := strconv.ParseFloat(raw, 64); errParse == nil && secs >= 0 {
			resetAt = q.ObservedAt.Add(time.Duration(secs * float64(time.Second)))
		}
	}
	if resetAt.IsZero() || !resetAt.After(now) {
		return time.Time{}, false
	}
	return resetAt, true
}

func parseUnixSeconds(raw string) time.Time {
	value, errParse := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if errParse != nil || value <= 0 {
		return time.Time{}
	}
	// Accept millisecond timestamps defensively.
	if value > 1e12 {
		value /= 1000
	}
	return time.Unix(int64(value), 0)
}

// pickEarliestReset returns the ready entry whose weekly window resets soonest.
func (v *readyView) pickEarliestReset(predicate func(*scheduledAuth) bool, now time.Time) *scheduledAuth {
	var best *scheduledAuth
	var bestKey resetRank
	for _, entry := range v.flat {
		if entry == nil || (predicate != nil && !predicate(entry)) {
			continue
		}
		key := weeklyResetRank(scheduledEntryAuth(entry), now)
		if best == nil || key.less(bestKey) {
			best, bestKey = entry, key
		}
	}
	return best
}

// scheduledEntryAuth prefers the latest auth snapshot recorded on the meta.
func scheduledEntryAuth(entry *scheduledAuth) *Auth {
	if entry == nil {
		return nil
	}
	if entry.meta != nil && entry.meta.auth != nil {
		return entry.meta.auth
	}
	return entry.auth
}
