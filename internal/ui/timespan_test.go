package ui

import (
	"fmt"
	"testing"
	"time"

	"kaudit-tui/internal/audit"
)

func TestParseSpan(t *testing.T) {
	ref := time.Date(2026, 11, 19, 14, 0, 0, 0, time.UTC)
	at := func(s string) time.Time {
		p, err := time.Parse("2006-01-02 15:04:05.999999999", s)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	for in, want := range map[string][2]string{
		"13:36":                                {"2026-11-19 13:21:00", "2026-11-19 13:51:00"},
		"15:00":                                {"2026-11-18 14:45:00", "2026-11-18 15:15:00"}, // after ref: yesterday
		"2026-11-18":                           {"2026-11-18 00:00:00", "2026-11-18 23:59:59.999999999"},
		"2026-11-19T13:36:10.525":              {"2026-11-19 13:21:10.525", "2026-11-19 13:51:10.525"},
		"13:36 ±10m":                           {"2026-11-19 13:26:00", "2026-11-19 13:46:00"},
		"13:36 +1h":                            {"2026-11-19 13:36:00", "2026-11-19 14:36:00"},
		"13:30-13:45":                          {"2026-11-19 13:30:00", "2026-11-19 13:45:59.999999999"},
		"2026-11-18 22:00 - 02:00":             {"2026-11-18 22:00:00", "2026-11-19 02:00:59.999999999"},
		"2026-11-17 .. 2026-11-18":             {"2026-11-17 00:00:00", "2026-11-18 23:59:59.999999999"},
		"2026-11-18 22:00 to 2026-11-19 02:00": {"2026-11-18 22:00:00", "2026-11-19 02:00:59.999999999"},
		"-30m":                                 {"2026-11-19 13:30:00", "2026-11-19 14:00:00"},
	} {
		from, to, err := parseSpan(in, ref)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if !from.Equal(at(want[0])) || !to.Equal(at(want[1])) {
			t.Errorf("%q = %s – %s, want %s – %s", in, from, to, want[0], want[1])
		}
	}
	for _, bad := range []string{"", "yesterday", "13:36 ±x", "2026-11-19 .. 2026-11-18"} {
		if _, _, err := parseSpan(bad, ref); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestAddEventsMerges(t *testing.T) {
	m := New(nil, "similar", "")
	at := func(h int) audit.Event { return audit.Event{Time: time.Date(2026, 11, 19, h, 0, 0, 0, time.UTC)} }
	m.addEvents([]audit.Event{at(5), at(9), at(7)})
	m.addEvents([]audit.Event{at(1), at(8)}) // older history from another host
	m.addEvents([]audit.Event{at(10)})
	var got []int
	for _, e := range m.all {
		got = append(got, e.Time.Hour())
	}
	if fmt.Sprint(got) != "[1 5 7 8 9 10]" {
		t.Fatalf("order %v", got)
	}
}
