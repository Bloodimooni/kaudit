package ui

import (
	"fmt"
	"strings"
	"time"
)

// defaultAround is the window shown around a single typed time.
const defaultAround = 15 * time.Minute

const spanHelp = "e.g. 13:36 · 2026-11-19 · 13:36 ±10m · 13:30-13:45 · 2026-11-18 22:00 .. 2026-11-19 02:00 · -30m"

// parseSpan turns what the user typed into a time window. Times are read in
// ref's location (the zone the UI shows), ref is the latest event.
//
//	2026-11-19                      that whole day
//	13:36, 2026-11-19 13:36:10.5    ±15m around that time
//	13:36 ±10m, 13:36 +1h           around / starting at that time
//	13:30-13:45, A .. B, A to B     a range; each end counts to its precision (13:45 = up to 13:45:59)
//	-30m, 2h                        the last 30 minutes / 2 hours before ref
//
// A time without a date means its latest occurrence not after ref; a range
// end without a date follows its start (22:00-02:00 crosses midnight).
func parseSpan(s string, ref time.Time) (time.Time, time.Time, error) {
	s = strings.TrimSpace(s)
	for _, sep := range []string{"–", "—", " to "} {
		s = strings.ReplaceAll(s, sep, "..")
	}
	s = strings.ReplaceAll(s, "T", " ")
	if s == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("empty time")
	}
	if d, err := time.ParseDuration(strings.TrimPrefix(s, "-")); err == nil && d > 0 {
		return ref.Add(-d), ref, nil
	}
	for _, op := range []string{"±", "+"} {
		if p, ds, ok := strings.Cut(s, op); ok {
			d, err := time.ParseDuration(strings.TrimSpace(ds))
			if err != nil || d <= 0 {
				return time.Time{}, time.Time{}, fmt.Errorf("bad duration %q", strings.TrimSpace(ds))
			}
			t, _, err := startPoint(p, ref)
			if err != nil {
				return time.Time{}, time.Time{}, err
			}
			if op == "+" {
				return t, t.Add(d), nil
			}
			return t.Add(-d), t.Add(d), nil
		}
	}
	if a, b, ok := strings.Cut(s, ".."); ok {
		return parseRange(a, b, ref)
	}
	// "-" is also inside dates, so try every dash as the range separator
	for i := range len(s) {
		if s[i] == '-' {
			if from, to, err := parseRange(s[:i], s[i+1:], ref); err == nil {
				return from, to, nil
			}
		}
	}
	t, prec, err := startPoint(s, ref)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if prec == 24*time.Hour {
		return t, t.Add(prec - time.Nanosecond), nil
	}
	return t.Add(-defaultAround), t.Add(defaultAround), nil
}

func parseRange(a, b string, ref time.Time) (time.Time, time.Time, error) {
	from, _, err := startPoint(a, ref)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	to, prec, hasDate, err := parsePoint(b, midnight(from))
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !hasDate && to.Before(from) {
		to = to.AddDate(0, 0, 1)
	}
	to = to.Add(prec - time.Nanosecond)
	if to.Before(from) {
		return time.Time{}, time.Time{}, fmt.Errorf("range ends before it starts")
	}
	return from, to, nil
}

// startPoint parses a point; without a date it is the latest one not after ref.
func startPoint(s string, ref time.Time) (time.Time, time.Duration, error) {
	t, prec, hasDate, err := parsePoint(s, midnight(ref))
	if err == nil && !hasDate && t.After(ref) {
		t = t.AddDate(0, 0, -1)
	}
	return t, prec, err
}

var pointLayouts = []struct {
	layout  string
	prec    time.Duration
	hasDate bool
}{
	{"2006-01-02", 24 * time.Hour, true},
	{"2006-01-02 15:04", time.Minute, true},
	{"2006-01-02 15:04:05", time.Second, true},
	{"2006-01-02 15:04:05.999999999", time.Nanosecond, true},
	{"15:04", time.Minute, false},
	{"15:04:05", time.Second, false},
	{"15:04:05.999999999", time.Nanosecond, false},
}

// parsePoint parses a date and/or time; a bare time is placed on day.
func parsePoint(s string, day time.Time) (t time.Time, prec time.Duration, hasDate bool, err error) {
	s = strings.Join(strings.Fields(s), " ")
	for _, l := range pointLayouts {
		p, err := time.ParseInLocation(l.layout, s, day.Location())
		if err != nil {
			continue
		}
		if !l.hasDate {
			p = day.Add(time.Duration(p.Hour())*time.Hour + time.Duration(p.Minute())*time.Minute +
				time.Duration(p.Second())*time.Second + time.Duration(p.Nanosecond()))
		}
		return p, l.prec, l.hasDate, nil
	}
	return time.Time{}, 0, false, fmt.Errorf("cannot read %q as a date or time", s)
}

func midnight(t time.Time) time.Time {
	y, mo, d := t.Date()
	return time.Date(y, mo, d, 0, 0, 0, 0, t.Location())
}
