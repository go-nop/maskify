package main

import (
	"fmt"

	"github.com/go-nop/maskify"
)

type User struct {
	SensitiveData string `mask:"start=2,end=2"`
}

type User2 struct {
	Password      string `masker:"asterisk"`
	SensitiveData string
}

func main() {
	// Create a new maskify instance.
	m := maskify.New()
	user := &User{
		SensitiveData: "abcdefgh",
	}

	fmt.Println("Before masking:", user.SensitiveData)

	err := m.Mask(user)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("After masking:", user.SensitiveData)

	// Create a new maskify instance with options.
	m = maskify.New(
		maskify.OptionTagName{
			Value: "masker",
		},
		maskify.OptionMaskByName{
			Value: map[string]maskify.MaskType{
				"SensitiveData": maskify.MaskCensor,
			},
		},
	)

	user2 := &User2{
		Password:      "password",
		SensitiveData: "this is sensitive data",
	}

	fmt.Println("Before masking:", user2.Password, user2.SensitiveData)

	err = m.Mask(user2)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("After masking:", user2.Password, user2.SensitiveData)
}
