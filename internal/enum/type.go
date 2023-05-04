package enum

type Type int

const (
	LogPass Type = iota
	Text
	File
	Card
)

func (t Type) String() string {
	return [...]string{"Login-Password", "Text", "File", "Bank Card"}[t]
}
