
# Maskify

`maskify` is a Go library used to mask fields in a struct. This library supports various types of masking such as censor, asterisk, email, credit card, phone, and zip code.

## Features

- Asterisk masking
- Censor masking
- Email masking
- Credit card number masking
- Phone number masking
- Zip code masking
- Custom masking with start and end positions
- Supports nested structs, slices, and maps

## Installation

You can install this library using `go get`:

```sh
go get github.com/go-nop/maskify
```

## Usage
Here is an example of how to use this library:

```go
package main

import (
    "fmt"
    "github.com/go-nop/maskify"
)

type User struct {
    Name       string `mask:"start=2,end=2"`
    Password   string `mask:"asterisk"`
    Email      string `mask:"email"`
    Phone      string `mask:"phone"`
    Zip        string `mask:"zip"`
    CreditCard string `mask:"credit_card"`
    TokenJWT   string `mask:"censor"`
}

func main() {
    m := maskify.New()
    user := &User{
        Name:       "John Doe",
        Password:   "supersecret",
        Email:      "john.doe@example.com",
        Phone:      "1234567890",
        Zip:        "10025",
        CreditCard: "1234 5678 1234 5678",
        TokenJWT:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    }

    fmt.Println("Before masking:", user)

    err := m.Mask(user)
    if err != nil {
        fmt.Println("Error:", err)
        return
    }

    fmt.Println("After masking:", user)
}
```

## Documentation
### MaskType
`MaskType` is a type used to specify the kind of masking to apply to a field. The available `MaskType` values are:

- `MaskAsterisk`: Masking with asterisks.
- `MaskCensor`: Masking with censor.
- `MaskEmail`: Masking email.
- `MaskCreditCard`: Masking credit card number.
- `MaskPhone`: Masking phone number.
- `MaskZip`: Masking zip code.

### Masking Tags
You can use the mask tag on struct fields to specify the type of masking to apply. Here is an example of using the mask tag:

```go
type User struct {
    Name       string `mask:"start=2,end=2"`
    Password   string `mask:"asterisk"`
    Email      string `mask:"email"`
    Phone      string `mask:"phone"`
    Zip        string `mask:"zip"`
    CreditCard string `mask:"credit_card"`
    TokenJWT   string `mask:"censor"`
}
```

### Functions
`New(opts ...Option) *Masker`: Creates a new instance of Masker with the given options.

`Mask(o interface{}) error`: Masks the fields of the given struct.

### Options
`Option` is a type used to specify options for the Masker. The available options are:

- `OptionTagName`: Specifies the tag name to use for the mask tag. Default is `mask`.

- `OptionMaskByName`: Specifies whether to mask fields by name.
