package validators

import "testing"

func TestValidateStrongPassword(t *testing.T) {
	tests := []struct {
		name    string
		pw      string
		wantErr bool
	}{
		{"too short", "Aa1!aaaa", true},
		{"no upper", "aaaabbbb1!!!", true},
		{"no lower", "AAAABBBB1!!!", true},
		{"no digit", "Aaaabbbbcc!!", true},
		{"no symbol", "Aaaabbbbcc12", true},
		{"has whitespace", "Aaaabbbb1! aa", true},
		{"leading whitespace", " Aaaabbbb1!!", true},
		{"valid minimal", "Aaaaaaaaaa1!", false},
		{"valid long", "CorrectHorseBatteryStaple1!", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStrongPassword(tc.pw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("got err=%v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !IsPasswordPolicyError(err) {
				t.Fatalf("expected PasswordPolicyError, got %T", err)
			}
		})
	}
}
