package test

import (
	"crypto/rand"
	"math/big"
)

// RandomString return a random alphanumeric string with length 10
func RandomString() string {
	return RandomStringWithLen(10)
}

// RandomStringWithLen returns a random alphanumeric string with a specified length
func RandomStringWithLen(length int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, length)
	for i := range s {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		s[i] = letters[n.Int64()]
	}
	return string(s)
}
