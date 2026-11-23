package runtime

// HintedError is a secret-free, user-facing explanation of a runtime failure.
// CLI output may append SafeHint(); raw causes such as os.ErrPermission stay
// wrapped and are not printed.
type HintedError struct {
	Hint string
}

func (e *HintedError) Error() string {
	if e == nil {
		return ""
	}
	return e.Hint
}

func (e *HintedError) SafeHint() string {
	return e.Error()
}

func newHintedError(hint string) error {
	if hint == "" {
		return nil
	}
	return &HintedError{Hint: hint}
}
