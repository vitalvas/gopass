package vault

import "testing"

func TestValidateName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"", false},
		{"a", false},
		{"aa", false},
		{"aaa", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"a a", false},
		{"a-a", true},
		{"a_a", true},
		{"a.a", true},
		{"a.a.a", true},
		{"a.a.a.a", true},
		{"aa+aa", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateName(tc.name)
			if tc.valid && err != nil {
				t.Errorf("expected valid name, got error: %v", err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected invalid name, got no error")
			}
		})
	}
}

func TestValidateKeyName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		valid bool
	}{
		{"", false},
		{"a", false},
		{"aa", false},
		{"aaa", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
		{"a a", false},
		{"a-a", true},
		{"a_a", true},
		{"a.a", true},
		{"a.a.a", true},
		{"a.a.a.a", true},
		{"aa+aa", false},
		{"social/facebook.com/username/me/password", true},
		{"social/instagram/username/name@example.com/password/extra", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKeyName(tc.name)
			if tc.valid && err != nil {
				t.Errorf("expected valid name, got error: %v", err)
			}
			if !tc.valid && err == nil {
				t.Errorf("expected invalid name, got no error")
			}
		})
	}
}
