// Package validators hosts small input validators shared across services.
package validators

import (
	"errors"
	"unicode"
)

// PasswordPolicyError is returned when a candidate password does not satisfy
// the portal password policy. The message is safe to show to end users.
type PasswordPolicyError struct {
	Reason string
}

func (e *PasswordPolicyError) Error() string { return e.Reason }

// MinPasswordLength is the minimum number of runes a password must contain.
const MinPasswordLength = 12

// ValidateStrongPassword enforces the portal password policy:
//   - at least MinPasswordLength runes
//   - at least one uppercase letter
//   - at least one lowercase letter
//   - at least one digit
//   - at least one non-alphanumeric symbol
//   - no whitespace (including leading/trailing)
//
// The function returns a *PasswordPolicyError on failure so callers can
// surface the exact reason in API responses.
func ValidateStrongPassword(pw string) error {
	var (
		runeCount                  int
		hasUpper, hasLower         bool
		hasDigit, hasSymbol, hasWS bool
	)

	for _, r := range pw {
		runeCount++
		switch {
		case unicode.IsSpace(r):
			hasWS = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsLetter(r):
			// Letters without an explicit case (e.g. CJK) count as lower so
			// users whose keyboards can't produce ASCII upper/lower aren't
			// locked out — the remaining classes still apply.
			hasLower = true
		default:
			hasSymbol = true
		}
	}

	switch {
	case runeCount < MinPasswordLength:
		return &PasswordPolicyError{Reason: "password must be at least 12 characters long"}
	case hasWS:
		return &PasswordPolicyError{Reason: "password must not contain whitespace"}
	case !hasUpper:
		return &PasswordPolicyError{Reason: "password must contain at least one uppercase letter"}
	case !hasLower:
		return &PasswordPolicyError{Reason: "password must contain at least one lowercase letter"}
	case !hasDigit:
		return &PasswordPolicyError{Reason: "password must contain at least one digit"}
	case !hasSymbol:
		return &PasswordPolicyError{Reason: "password must contain at least one symbol"}
	}

	return nil
}

// IsPasswordPolicyError reports whether err is a password-policy error.
func IsPasswordPolicyError(err error) bool {
	var perr *PasswordPolicyError
	return errors.As(err, &perr)
}
