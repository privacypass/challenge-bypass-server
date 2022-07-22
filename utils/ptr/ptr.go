package ptr

import "time"

// FromString returns pointer to string
func FromString(s string) *string {
	return &s
}

// String returns value of pointer or empty string
func String(s *string) string {
	return StringOr(s, "")
}

// StringOr returns value of pointer or alternative value
func StringOr(s *string, or string) string {
	if s == nil {
		return or
	}
	return *s
}

func FromTime(t time.Time) *time.Time {
	return &t
}
