package customValidator

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

var opaqueTokenFormat = regexp.MustCompile(`^[0-9a-fA-F-]{36}\.[A-Za-z0-9_-]+$`)

func New() *validator.Validate {
	v := validator.New()

	registerCustomValidators(v)

	return v
}

func registerCustomValidators(v *validator.Validate) {
	if err := v.RegisterValidation("reset_token_format", func(fl validator.FieldLevel) bool {
		return opaqueTokenFormat.MatchString(fl.Field().String())
	}); err != nil {
		panic(err)
	}

	if err := v.RegisterValidation("refresh_token_format", func(fl validator.FieldLevel) bool {
		return opaqueTokenFormat.MatchString(fl.Field().String())
	}); err != nil {
		panic(err)
	}
}
