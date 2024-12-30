package maskify

import (
	"reflect"
	"strconv"
	"strings"
)

// MaskType represents the type of mask to apply to a field.

/*
The mask type can be one of the following:

  - MaskCensor to censor the value. For example, "this is value" -> "[CENSORED]".
  - MaskAsterisk to mask the value with asterisks. For example, "this is value" -> "**** ** *****".
  - MaskCreditCard to mask the value as a credit card. For example, "1234 5678 1234 5678" -> "1234 56** **** 5678".
  - MaskEmail to mask the value as an email. For example, "example@go-nop.id" -> "ex***e@g****p.id".
  - MaskPhone to mask the value as a phone number. For example, "081234567890" -> "0812*****890".
  - MaskZip to mask the value as a zip code. For example, "12345" -> "1***5".
*/
type MaskType string

const (
	// MaskAsterisk applies an asterisk mask.
	MaskAsterisk MaskType = "asterisk"
	// MaskCensor applies a censored mask.
	MaskCensor MaskType = "censor"
	// MaskEmail applies an email mask.
	MaskEmail MaskType = "email"
	// MaskCreditCard applies a credit card mask.
	MaskCreditCard MaskType = "credit_card"
	// MaskPhone applies a phone number mask.
	MaskPhone MaskType = "phone"
	// MaskZip applies a zip code mask.
	MaskZip MaskType = "zip"
)

const (
	// Asterisk is the asterisk mask.
	Asterisk string = "*"
	// Censored is the censored mask.
	Censored string = "[CENSORED]"
)

const (
	// TagName is the tag name for the mask.
	tagName = "mask"
)

// Masker is a representation of a masker.
type Masker struct {
	tagName    string
	maskByName map[string]MaskType
}

// New is a constructor for a Masker.
func New(opts ...Option) *Masker {
	m := &Masker{
		tagName: tagName,
	}

	for _, opt := range opts {
		switch opt.identifier() {
		case TagNameID:
			m.tagName = opt.value().(string)
		case MaskByNameID:
			m.maskByName = opt.value().(map[string]MaskType)
		}
	}

	return m
}

// Mask is a method to mask a field.
func (m *Masker) Mask(o interface{}) error {
	return m.maskRecurse(reflect.ValueOf(o).Elem())
}

// maskRecurse is a recursive method to mask a field.
func (m Masker) maskRecurse(v reflect.Value) error {
	// Loop through the fields of the struct
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		fKind := field.Kind()

		switch fKind {
		case reflect.Struct:
			_ = m.maskRecurse(field)
		case reflect.String:
			// check if the field mask by name
			// if the field mask by name, mask the string
			// if the field does not mask by name, continue
			if maskType, ok := m.maskByName[v.Type().Field(i).Name]; ok {
				masked, err := masking(field, map[string]string{string(maskType): ""})
				if err == nil && field.CanSet() {
					field.SetString(masked)
					continue
				}
			}

			// check if the field has a tag
			// if the field has a tag, mask the string
			// if the field does not have a tag, continue
			tags := m.fieldTags(v.Type().Field(i).Tag)
			if len(tags) == 0 {
				continue
			}

			masked, err := masking(field, tags)
			if err == nil && field.CanSet() {
				field.SetString(masked)
			}

		case reflect.Slice, reflect.Array:
			for j := 0; j < field.Len(); j++ {
				if field.Index(j).Kind() == reflect.Struct {
					_ = m.maskRecurse(field.Index(j))
				} else if field.Index(j).Kind() == reflect.Ptr && field.Index(j).Elem().Kind() == reflect.Struct {
					_ = m.maskRecurse(field.Index(j).Elem())
				}
			}
		case reflect.Map:
			keys := field.MapKeys()
			for _, k := range keys {
				elem := field.MapIndex(k)
				if elem.Kind() == reflect.Struct {
					newElem := reflect.New(elem.Type()).Elem()
					newElem.Set(elem)
					_ = m.maskRecurse(newElem)
					field.SetMapIndex(k, newElem)
				} else if elem.Kind() == reflect.Ptr && elem.Elem().Kind() == reflect.Struct {
					_ = m.maskRecurse(elem.Elem())
				}
			}
		case reflect.Ptr:
			if !field.IsNil() {
				_ = m.maskRecurse(field.Elem())
			}
		case reflect.Interface:
			if !field.IsNil() {
				_ = m.maskRecurse(field.Elem())
			}
		default:
			// do nothing
		}
	}

	return nil
}

// masking is a method to mask a field.
func masking(v reflect.Value, tags map[string]string) (string, error) {
	// check key 'start' and 'end' in the tags
	if startIdx, ok := tags["start"]; ok {
		if endIdx, ok := tags["end"]; ok {
			return maskString(v.String(), mustAtoi(startIdx), mustAtoi(endIdx)), nil
		}
	}

	// mask for censor
	if _, ok := tags[string(MaskCensor)]; ok {
		if v.String() == "" {
			return "", nil
		}
		return Censored, nil
	}

	// mask for email
	if _, ok := tags[string(MaskEmail)]; ok {
		return maskEmail(v)
	}

	// mask for credit card
	if _, ok := tags[string(MaskCreditCard)]; ok {
		return maskCreditCard(v)
	}

	// mask for asterisk
	if _, ok := tags[string(MaskAsterisk)]; ok {
		return strings.Repeat(Asterisk, len(v.String())), nil
	}

	// mask for phone
	if _, ok := tags[string(MaskPhone)]; ok {
		return maskString(v.String(), 4, 3), nil
	}

	// mask for zip
	if _, ok := tags[string(MaskZip)]; ok {
		return maskString(v.String(), 1, 1), nil
	}

	return v.String(), nil
}

// maskString is a method to mask a string.
func maskString(s string, startIdx, endIdx int) string {
	// "this is value"
	// start = 2
	// end = 2
	// "th** ** ***ue"
	var sb strings.Builder
	endIdx = len(s) - endIdx - 1

	for i, c := range s {
		if i >= startIdx && i <= endIdx && c != ' ' {
			sb.WriteString(Asterisk)
		} else {
			sb.WriteRune(c)
		}
	}

	return sb.String()
}

// maskEmail is a method to mask an email.
func maskEmail(v reflect.Value) (string, error) {
	// "example@go-nop.id"
	// "ex***e@g****p.id"
	var (
		sb strings.Builder
	)

	// split the email into username and domain
	// mask the username
	// mask the domain
	// combine the username and domain
	email := v.String()
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email, nil
	}

	// mask the username
	sb.WriteString(maskString(parts[0], 2, 2))

	// mask the domain
	sb.WriteRune('@')
	sb.WriteString(maskString(parts[1], 2, 2))

	return sb.String(), nil
}

// maskCreditCard is a method to mask a credit card.
func maskCreditCard(v reflect.Value) (string, error) {
	// "1234 5678 1234 5678"
	// "1234 56** **** 5678"
	var (
		sb strings.Builder
	)

	// split the credit
	// mask the credit
	// combine the credit
	cc := v.String()
	for i, c := range cc {
		switch {
		case c == ' ' || c == '-':
			sb.WriteRune(c)
		case i < 4 || i > len(cc)-3:
			sb.WriteRune(c)
		default:
			sb.WriteString(Asterisk)
		}
	}

	return sb.String(), nil
}

// mustAtoi is a method to convert a string to an integer.
func mustAtoi(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}

	return i
}
