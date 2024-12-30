package maskify

import (
	"reflect"
	"strings"
)

// fieldTags is a method to get the tags of a field.
func (m Masker) fieldTags(f reflect.StructTag) map[string]string {
	tags := f.Get(m.tagName)
	if tags == "" {
		return nil
	}

	ms := make(map[string]string)

	// tag present - process tag string into key-value pairs (ex.
	// "partial,start=3,end=5" -> map[string]string{"start": "3", "end": "5"})
	comps := strings.Split(tags, ",")
	for _, comp := range comps {
		if strings.Contains(comp, "=") {
			// Use as param. Ex. 'start=3'
			kv := strings.Split(comp, "=")
			ms[kv[0]] = kv[1]
		} else {
			// Use directly. Ex. 'password'
			ms[comp] = ""
		}
	}

	return ms
}
