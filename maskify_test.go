package maskify_test

import (
	"testing"

	"github.com/go-nop/maskify"
)

type TestStruct struct {
	Name       string `mask:"start=2,end=2"`
	Password   string `mask:"asterisk"`
	Email      string `mask:"email"`
	Phone      string `mask:"phone"`
	Zip        string `mask:"zip"`
	CreditCard string `mask:"credit_card"`
	TokenJWT   string `mask:"censor"`
}

type TestNestedStruct struct {
	Struct1             TestStruct
	SensitiveDataNested TestStruct
}

type TestMultipleTypes struct {
	Email      string `mask:"email"`
	Phone      string `mask:"phone"`
	Zip        string `mask:"zip"`
	CreditCard string `mask:"credit_card"`
	Objects    []TestStruct
	Maps       map[string]*TestStruct
	Ptr        *TestStruct
}

func TestMask(t *testing.T) {
	m := maskify.New()
	input := &TestStruct{
		Name:       "John Doe",
		Password:   "supersecret",
		Email:      "john.doe@example.com",
		Phone:      "1234567890",
		Zip:        "10025",
		CreditCard: "1234 5678 1234 5678",
		TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}

	expected := &TestStruct{
		Name:       "Jo** *oe",
		Password:   "***********",
		Email:      "jo****oe@ex*******om",
		Phone:      "1234***890",
		Zip:        "1***5",
		CreditCard: "1234 **** **** **78",
		TokenJWT:   "[CENSORED]",
	}

	err := m.Mask(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if input.Name != expected.Name {
		t.Errorf("expected %s, got %s", expected.Name, input.Name)
	}
	if input.Password != expected.Password {
		t.Errorf("expected %s, got %s", expected.Password, input.Password)
	}
	if input.Email != expected.Email {
		t.Errorf("expected %s, got %s", expected.Email, input.Email)
	}
	if input.Phone != expected.Phone {
		t.Errorf("expected %s, got %s", expected.Phone, input.Phone)
	}
	if input.Zip != expected.Zip {
		t.Errorf("expected %s, got %s", expected.Zip, input.Zip)
	}
	if input.CreditCard != expected.CreditCard {
		t.Errorf("expected %s, got %s", expected.CreditCard, input.CreditCard)
	}
	if input.TokenJWT != expected.TokenJWT {
		t.Errorf("expected %s, got %s", expected.TokenJWT, input.TokenJWT)
	}
}

func TestMaskNestedStruct(t *testing.T) {
	m := maskify.New()
	input := &TestNestedStruct{
		Struct1: TestStruct{
			Name:       "John Doe",
			Password:   "supersecret",
			Email:      "john.doe@example.com",
			Phone:      "1234567890",
			Zip:        "10025",
			CreditCard: "1234 5678 1234 5678",
			TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		SensitiveDataNested: TestStruct{
			Name:       "Jane Doe",
			Password:   "anothersecret",
			Email:      "jane.doe@example.com",
			Phone:      "0987654321",
			Zip:        "54321",
			CreditCard: "8765 4321 8765 4321",
			TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ8",
		},
	}

	expected := &TestNestedStruct{
		Struct1: TestStruct{
			Name:       "Jo** *oe",
			Password:   "***********",
			Email:      "jo****oe@ex*******om",
			Phone:      "1234***890",
			Zip:        "1***5",
			CreditCard: "1234 **** **** **78",
			TokenJWT:   "[CENSORED]",
		},
		SensitiveDataNested: TestStruct{
			Name:       "Ja** *oe",
			Password:   "*************",
			Email:      "ja****oe@ex*******om",
			Phone:      "0987***321",
			Zip:        "5***1",
			CreditCard: "8765 **** **** **21",
			TokenJWT:   "[CENSORED]",
		},
	}

	err := m.Mask(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if input.Struct1.Name != expected.Struct1.Name {
		t.Errorf("expected %s, got %s", expected.Struct1.Name, input.Struct1.Name)
	}
	if input.Struct1.Password != expected.Struct1.Password {
		t.Errorf("expected %s, got %s", expected.Struct1.Password, input.Struct1.Password)
	}
	if input.Struct1.Email != expected.Struct1.Email {
		t.Errorf("expected %s, got %s", expected.Struct1.Email, input.Struct1.Email)
	}
	if input.Struct1.Phone != expected.Struct1.Phone {
		t.Errorf("expected %s, got %s", expected.Struct1.Phone, input.Struct1.Phone)
	}
	if input.Struct1.Zip != expected.Struct1.Zip {
		t.Errorf("expected %s, got %s", expected.Struct1.Zip, input.Struct1.Zip)
	}
	if input.Struct1.CreditCard != expected.Struct1.CreditCard {
		t.Errorf("expected %s, got %s", expected.Struct1.CreditCard, input.Struct1.CreditCard)
	}
	if input.Struct1.TokenJWT != expected.Struct1.TokenJWT {
		t.Errorf("expected %s, got %s", expected.Struct1.TokenJWT, input.Struct1.TokenJWT)
	}

	if input.SensitiveDataNested.Name != expected.SensitiveDataNested.Name {
		t.Errorf("expected %s, got %s", expected.SensitiveDataNested.Name, input.SensitiveDataNested.Name)
	}
	if input.SensitiveDataNested.Password != expected.SensitiveDataNested.Password {
		t.Errorf("expected %s, got %s", expected.SensitiveDataNested.Password, input.SensitiveDataNested.Password)
	}
	if input.SensitiveDataNested.Email != expected.SensitiveDataNested.Email {
		t.Errorf("expected %s, got %s", expected.SensitiveDataNested.Email, input.SensitiveDataNested.Email)
	}
	if input.SensitiveDataNested.Phone != expected.SensitiveDataNested.Phone {
		t.Errorf("expected %s, got %s", expected.SensitiveDataNested.Phone, input.SensitiveDataNested.Phone)
	}
	if input.SensitiveDataNested.Zip != expected.SensitiveDataNested.Zip {
		t.Errorf("expected %s, got %s", expected.SensitiveDataNested.Zip, input.SensitiveDataNested.Zip)
	}
	if input.SensitiveDataNested.CreditCard != expected.SensitiveDataNested.CreditCard {
		t.Errorf("expected %s, got %s", expected.SensitiveDataNested.CreditCard, input.SensitiveDataNested.CreditCard)
	}
	if input.SensitiveDataNested.TokenJWT != expected.SensitiveDataNested.TokenJWT {
		t.Errorf("expected %s, got %s", expected.SensitiveDataNested.TokenJWT, input.SensitiveDataNested.TokenJWT)
	}
}

func TestMaskMultipleTypes(t *testing.T) {
	m := maskify.New()
	input := &TestMultipleTypes{
		Email:      "john.doe@example.com",
		Phone:      "1234567890",
		Zip:        "10025",
		CreditCard: "1234 5678 1234 5678",
		Objects: []TestStruct{
			{Name: "John Doe", Password: "supersecret"},
		},
		Maps: map[string]*TestStruct{
			"key1": {Name: "Jane Doe", Password: "anothersecret"},
		},
		Ptr: &TestStruct{
			Name:       "John Doe",
			Password:   "supersecret",
			Email:      "john.doe@example.com",
			Phone:      "1234567890",
			Zip:        "10025",
			CreditCard: "1234 5678 1234 5678",
			TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
	}

	expected := &TestMultipleTypes{
		Email:      "jo****oe@ex*******om",
		Phone:      "1234***890",
		Zip:        "1***5",
		CreditCard: "1234 **** **** **78",
		Objects: []TestStruct{
			{Name: "Jo** *oe", Password: "***********"},
		},
		Maps: map[string]*TestStruct{
			"key1": {Name: "Ja** *oe", Password: "*************"},
		},
		Ptr: &TestStruct{
			Name:       "Jo** *oe",
			Password:   "***********",
			Email:      "jo****oe@ex*******om",
			Phone:      "1234***890",
			Zip:        "1***5",
			CreditCard: "1234 **** **** **78",
			TokenJWT:   "[CENSORED]",
		},
	}

	err := m.Mask(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if input.Email != expected.Email {
		t.Errorf("expected %s, got %s", expected.Email, input.Email)
	}
	if input.Phone != expected.Phone {
		t.Errorf("expected %s, got %s", expected.Phone, input.Phone)
	}
	if input.Zip != expected.Zip {
		t.Errorf("expected %s, got %s", expected.Zip, input.Zip)
	}
	if input.CreditCard != expected.CreditCard {
		t.Errorf("expected %s, got %s", expected.CreditCard, input.CreditCard)
	}

	for i, obj := range input.Objects {
		if obj.Name != expected.Objects[i].Name {
			t.Errorf("expected %s, got %s", expected.Objects[i].Name, obj.Name)
		}
		if obj.Password != expected.Objects[i].Password {
			t.Errorf("expected %s, got %s", expected.Objects[i].Password, obj.Password)
		}
	}

	for key, obj := range input.Maps {
		if obj.Name != expected.Maps[key].Name {
			t.Errorf("expected %s, got %s", expected.Maps[key].Name, obj.Name)
		}
		if obj.Password != expected.Maps[key].Password {
			t.Errorf("expected %s, got %s", expected.Maps[key].Password, obj.Password)
		}
	}
}

func TestMaskWithOption(t *testing.T) {
	m := maskify.New(maskify.OptionTagName{
		Value: "nomask",
	})

	input := &TestStruct{
		Name: "John Doe",
	}

	expected := &TestStruct{
		Name: "John Doe",
	}

	err := m.Mask(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if input.Name != expected.Name {
		t.Errorf("expected %s, got %s", expected.Name, input.Name)
	}

	m = maskify.New(
		maskify.OptionMaskByName{
			Value: map[string]maskify.MaskType{
				"Name":  maskify.MaskCensor,
				"Phone": maskify.MaskAsterisk,
			},
		},
	)

	input = &TestStruct{
		Name:  "John Doe",
		Phone: "1234567890",
	}

	expected = &TestStruct{
		Name:  "[CENSORED]",
		Phone: "**********",
	}

	err = m.Mask(input)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if input.Name != expected.Name {
		t.Errorf("expected %s, got %s", expected.Name, input.Name)
	}
	if input.Phone != expected.Phone {
		t.Errorf("expected %s, got %s", expected.Phone, input.Phone)
	}
}

func BenchmarkMask(b *testing.B) {
	m := maskify.New()
	input := &TestStruct{
		Name:       "John Doe",
		Password:   "supersecret",
		Email:      "john.doe@example.com",
		Phone:      "1234567890",
		Zip:        "10025",
		CreditCard: "1234 5678 1234 5678",
		TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
	}

	for i := 0; i < b.N; i++ {
		_ = m.Mask(input)
	}
}

func BenchmarkMaskNestedStruct(b *testing.B) {
	m := maskify.New()
	input := &TestNestedStruct{
		Struct1: TestStruct{
			Name:       "John Doe",
			Password:   "supersecret",
			Email:      "john.doe@example.com",
			Phone:      "1234567890",
			Zip:        "10025",
			CreditCard: "1234 5678 1234 5678",
			TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		SensitiveDataNested: TestStruct{
			Name:       "Jane Doe",
			Password:   "anothersecret",
			Email:      "jane.doe@example.com",
			Phone:      "0987654321",
			Zip:        "54321",
			CreditCard: "8765 4321 8765 4321",
			TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ8",
		},
	}

	for i := 0; i < b.N; i++ {
		_ = m.Mask(input)
	}
}
