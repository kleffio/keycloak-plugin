package domain

import "errors"

// ErrUnauthorized is returned when credentials are invalid or a token fails verification.
type ErrUnauthorized struct{ Msg string }

func (e *ErrUnauthorized) Error() string { return e.Msg }

// ErrConflict is returned when a resource (e.g. user) already exists.
type ErrConflict struct{ Msg string }

func (e *ErrConflict) Error() string { return e.Msg }

// IsUnauthorized reports whether err is or wraps ErrUnauthorized.
func IsUnauthorized(err error) bool {
	var e *ErrUnauthorized
	return errors.As(err, &e)
}

// IsConflict reports whether err is or wraps ErrConflict.
func IsConflict(err error) bool {
	var e *ErrConflict
	return errors.As(err, &e)
}
