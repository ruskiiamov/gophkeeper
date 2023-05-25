// Package enum is the shared enumerations for the whole application.
package enum

// Type is the available data type for storing.
type Type int

const (
	// Login-password type.
	LogPass Type = iota + 1

	// Text type.
	Text

	// Binary file type.
	File

	// Bank card type.
	Card
)

// String is the Stringer interface implementation for the Type enum.
func (t Type) String() string {
	if !t.Valid() {
		return ""
	}

	return [...]string{"", "Login-Password", "Text", "File", "Bank Card"}[t]
}

// Valid returns true if the Type is OK.
func (t Type) Valid() bool {
	return t >= LogPass && t <= Card
}
