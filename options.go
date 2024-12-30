package maskify

// Option represents an optional setting for the maskify package.
type Option interface {
	identifier() string
	value() any
}

const (
	// TagNameID is the ID for the tag name option.
	TagNameID = "TagName"
	// MaskByNameID is the ID for the mask by name option.
	MaskByNameID = "MaskByName"
)

// OptionTagName is an option to set the tag name for the mask.
type OptionTagName struct {
	Value string `example:"mask"`
}

var _ Option = OptionTagName{}

// identifier is a method to get the ID of the option.
func (o OptionTagName) identifier() string {
	return TagNameID
}

// value is a method to get the value of the option.
func (o OptionTagName) value() any {
	return o.Value
}

// OptionMaskByName is an option to set the mask by name.
type OptionMaskByName struct {
	// Value is the value of the option.
	// The key is the name of the mask, and the value is the mask type.
	Value map[string]MaskType
}

var _ Option = OptionMaskByName{}

// identifier is a method to get the ID of the option.
func (o OptionMaskByName) identifier() string {
	return MaskByNameID
}

// value is a method to get the value of the option.
func (o OptionMaskByName) value() any {
	return o.Value
}
