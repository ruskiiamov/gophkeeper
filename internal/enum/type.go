package enum

type Type int

const (
	LogPass Type = iota + 1
	Text
	File
	Card
)

func (t Type) String() string {
	if !t.Valid() {
		return ""
	}

	return [...]string{"", "Login-Password", "Text", "File", "Bank Card"}[t]
}

func (t Type) Valid() bool {
	return t >= LogPass && t <= Card
}
