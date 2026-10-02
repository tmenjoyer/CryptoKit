package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/big"
	"strings"
	"unicode"
)

// ---------- hashing ----------

func newHash(name string) (hash.Hash, error) {
	switch strings.ToLower(name) {
	case "md5":
		return md5.New(), nil
	case "sha1":
		return sha1.New(), nil
	case "sha256":
		return sha256.New(), nil
	case "sha384":
		return sha512.New384(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("unsupported algorithm %q (md5, sha1, sha256, sha384, sha512)", name)
}

func hashReader(r io.Reader, algo string) (string, error) {
	h, err := newHash(algo)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ---------- hash identification ----------

func identifyHash(s string) []string {
	s = strings.TrimSpace(s)
	switch {
	case strings.HasPrefix(s, "$2a$"), strings.HasPrefix(s, "$2b$"), strings.HasPrefix(s, "$2y$"):
		return []string{"bcrypt"}
	case strings.HasPrefix(s, "$argon2"):
		return []string{"Argon2"}
	case strings.HasPrefix(s, "$6$"):
		return []string{"SHA-512 crypt (Unix)"}
	case strings.HasPrefix(s, "$5$"):
		return []string{"SHA-256 crypt (Unix)"}
	case strings.HasPrefix(s, "$1$"):
		return []string{"MD5 crypt (Unix)"}
	}
	if _, err := hex.DecodeString(s); err != nil {
		return nil
	}
	switch len(s) {
	case 32:
		return []string{"MD5", "NTLM", "MD4"}
	case 40:
		return []string{"SHA-1", "RIPEMD-160"}
	case 56:
		return []string{"SHA-224", "SHA3-224"}
	case 64:
		return []string{"SHA-256", "SHA3-256", "BLAKE2s-256"}
	case 96:
		return []string{"SHA-384", "SHA3-384"}
	case 128:
		return []string{"SHA-512", "SHA3-512", "BLAKE2b-512"}
	}
	return nil
}

// ---------- password generation ----------

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.<>?/~"
)

func randInt(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, err
	}
	return int(v.Int64()), nil
}

func generatePassword(length int, useSymbols bool) (string, error) {
	sets := []string{lower, upper, digits}
	if useSymbols {
		sets = append(sets, symbols)
	}
	if length < len(sets) {
		return "", fmt.Errorf("length must be at least %d", len(sets))
	}
	all := strings.Join(sets, "")
	out := make([]byte, 0, length)
	// guarantee one character from each class
	for _, s := range sets {
		i, err := randInt(len(s))
		if err != nil {
			return "", err
		}
		out = append(out, s[i])
	}
	for len(out) < length {
		i, err := randInt(len(all))
		if err != nil {
			return "", err
		}
		out = append(out, all[i])
	}
	// Fisher-Yates shuffle
	for i := len(out) - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

// ---------- password strength ----------

var commonPasswords = map[string]bool{
	"password": true, "123456": true, "12345678": true, "qwerty": true, "azerty": true,
	"letmein": true, "admin": true, "welcome": true, "iloveyou": true, "monkey": true,
	"dragon": true, "football": true, "abc123": true, "111111": true, "000000": true,
	"motdepasse": true, "password1": true, "123456789": true, "qwertyuiop": true,
}

type strength struct {
	Entropy float64
	Rating  string
	Notes   []string
}

func assessPassword(p string) (strength, error) {
	if p == "" {
		return strength{}, errors.New("empty password")
	}
	var s strength
	var hasLo, hasUp, hasDi, hasSy bool
	for _, r := range p {
		switch {
		case unicode.IsLower(r):
			hasLo = true
		case unicode.IsUpper(r):
			hasUp = true
		case unicode.IsDigit(r):
			hasDi = true
		default:
			hasSy = true
		}
	}
	pool := 0
	if hasLo {
		pool += 26
	}
	if hasUp {
		pool += 26
	}
	if hasDi {
		pool += 10
	}
	if hasSy {
		pool += 33
	}
	n := len([]rune(p))
	s.Entropy = float64(n) * math.Log2(float64(pool))

	if commonPasswords[strings.ToLower(p)] {
		s.Notes = append(s.Notes, "appears in common-password lists")
		s.Entropy = math.Min(s.Entropy, 10)
	}
	if n < 12 {
		s.Notes = append(s.Notes, "shorter than 12 characters")
	}
	if hasRepeats(p) {
		s.Notes = append(s.Notes, "contains repeated characters (e.g. 'aaa')")
		s.Entropy *= 0.8
	}
	if hasSequence(strings.ToLower(p)) {
		s.Notes = append(s.Notes, "contains a sequence (e.g. 'abc', '123')")
		s.Entropy *= 0.8
	}
	if !(hasLo && hasUp && hasDi && hasSy) {
		s.Notes = append(s.Notes, "does not mix lowercase, uppercase, digits and symbols")
	}

	switch {
	case s.Entropy < 28:
		s.Rating = "VERY WEAK"
	case s.Entropy < 40:
		s.Rating = "WEAK"
	case s.Entropy < 60:
		s.Rating = "FAIR"
	case s.Entropy < 80:
		s.Rating = "STRONG"
	default:
		s.Rating = "VERY STRONG"
	}
	return s, nil
}

func hasRepeats(p string) bool {
	r := []rune(p)
	for i := 0; i+2 < len(r); i++ {
		if r[i] == r[i+1] && r[i] == r[i+2] {
			return true
		}
	}
	return false
}

func hasSequence(p string) bool {
	r := []rune(p)
	for i := 0; i+2 < len(r); i++ {
		if r[i+1] == r[i]+1 && r[i+2] == r[i]+2 {
			return true
		}
	}
	return false
}
