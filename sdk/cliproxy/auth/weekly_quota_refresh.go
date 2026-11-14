package auth

import (
	"maps"
	"strconv"
	"strings"
	"time"
)

// Weekly reset signal keys read by WeeklyQuotaResetAt. Active refreshes write
// the same keys passive header observation produces so the selector does not
// need to know where a reset time came from.
const (
	claudeWeeklyResetSignal            = "Anthropic-Ratelimit-Unified-7d-Reset"
	codexWeeklyResetAtSignal           = "X-Codex-Secondary-Reset-At"
	codexWeeklyResetAfterSecondsSignal = "X-Codex-Secondary-Reset-After-Seconds"
)

// ResetFirstRoutingActive reports whether the configured selector drains
// credentials by soonest weekly reset, directly or as the session-affinity
// fallback.
func (m *Manager) ResetFirstRoutingActive() bool {
	if m == nil {
		return false
	}
	return selectorUsesResetFirst(m.Selector())
}

func selectorUsesResetFirst(selector Selector) bool {
	switch typed := selector.(type) {
	case *ResetFirstSelector:
		return true
	case *SessionAffinitySelector:
		if typed == nil {
			return false
		}
		_, ok := typed.fallback.(*ResetFirstSelector)
		return ok
	default:
		return false
	}
}

// ApplyWeeklyQuotaReset records an actively fetched weekly quota reset for a
// Claude or Codex credential. Only the weekly reset signal is written; other
// passively observed signals (status, utilization, retry hints) are kept so an
// active probe can never change cooldown or availability decisions. The
// snapshot timestamp only moves forward, and only when no passive snapshot is
// present, so a newer passive observation keeps its authority.
//
// It returns true when the stored reset changed and the scheduler was updated.
func (m *Manager) ApplyWeeklyQuotaReset(authID string, resetAt, observedAt time.Time) bool {
	if m == nil || strings.TrimSpace(authID) == "" || resetAt.IsZero() {
		return false
	}
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	releaseMutation := m.lockAuthMutation(authID)
	m.mu.Lock()
	auth, ok := m.auths[authID]
	var snapshot *Auth
	if ok && auth != nil {
		if applyWeeklyResetSignal(&auth.Quota, auth.Provider, resetAt, observedAt) {
			auth.Generation++
			auth.UpdatedAt = time.Now()
			snapshot = auth.Clone()
		}
	}
	m.mu.Unlock()
	releaseMutation()
	if snapshot == nil {
		return false
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuthResult(snapshot, nil, true)
	}
	return true
}

// applyWeeklyResetSignal merges the weekly reset into q. It returns false when
// the provider is unsupported or the stored value already matches.
func applyWeeklyResetSignal(q *QuotaState, provider string, resetAt, observedAt time.Time) bool {
	if q == nil {
		return false
	}
	value := strconv.FormatInt(resetAt.Unix(), 10)
	var key string
	var drop []string
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		key = claudeWeeklyResetSignal
	case "codex":
		key = codexWeeklyResetAtSignal
		// The relative form is anchored to ObservedAt, which an active refresh
		// does not own; the absolute form takes precedence anyway.
		drop = []string{codexWeeklyResetAfterSecondsSignal}
	default:
		return false
	}
	next := maps.Clone(q.Signals)
	if next == nil {
		next = make(map[string]string, 1)
	}
	changed := false
	for existing := range next {
		if strings.EqualFold(existing, key) && existing != key {
			delete(next, existing)
			changed = true
		}
		for _, name := range drop {
			if strings.EqualFold(existing, name) {
				delete(next, existing)
				changed = true
			}
		}
	}
	if next[key] != value {
		next[key] = value
		changed = true
	}
	if !changed {
		return false
	}
	q.Signals = next
	if q.ObservedAt.IsZero() {
		q.ObservedAt = observedAt
	}
	return true
}
