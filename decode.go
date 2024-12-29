package libjwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

func Decode(token string) (data map[string]interface{}, err error) {
	data = make(map[string]interface{})

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return data, errors.New("invalid token")
	}

	payloadDecode, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return data, err
	}

	err = json.Unmarshal(payloadDecode, &data)
	if err != nil {
		panic(err)
	}
	return data, nil
}
