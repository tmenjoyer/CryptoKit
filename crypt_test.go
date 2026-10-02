package main

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func roundTrip(t *testing.T, size int) {
	t.Helper()
	data := make([]byte, size)
	rand.Read(data)
	var enc, dec bytes.Buffer
	if err := encryptStream(bytes.NewReader(data), &enc, []byte("pw"), 1000); err != nil {
		t.Fatal(err)
	}
	if err := decryptStream(bytes.NewReader(enc.Bytes()), &dec, []byte("pw")); err != nil {
		t.Fatalf("size %d: %v", size, err)
	}
	if !bytes.Equal(data, dec.Bytes()) {
		t.Fatalf("size %d: mismatch", size)
	}
}

func TestRoundTrip(t *testing.T) {
	for _, s := range []int{0, 1, 100, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 7, 2 * chunkSize} {
		roundTrip(t, s)
	}
}

func TestWrongPasswordAndTamper(t *testing.T) {
	data := bytes.Repeat([]byte("A"), 3*chunkSize)
	var enc bytes.Buffer
	encryptStream(bytes.NewReader(data), &enc, []byte("good"), 1000)

	if err := decryptStream(bytes.NewReader(enc.Bytes()), &bytes.Buffer{}, []byte("bad")); err == nil {
		t.Fatal("wrong password accepted")
	}
	b := append([]byte{}, enc.Bytes()...)
	b[len(b)/2] ^= 1
	if err := decryptStream(bytes.NewReader(b), &bytes.Buffer{}, []byte("good")); err == nil {
		t.Fatal("tampering not detected")
	}
	// truncate on a chunk boundary
	cut := headerLen + 2*(chunkSize+tagLen)
	if err := decryptStream(bytes.NewReader(enc.Bytes()[:cut]), &bytes.Buffer{}, []byte("good")); err == nil {
		t.Fatal("truncation not detected")
	}
}

func TestPBKDF2Vector(t *testing.T) {
	// RFC 7914 / well-known PBKDF2-HMAC-SHA256 vector: "password"/"salt", 1 iter, 32 bytes
	got := pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32)
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if hexs(got) != want {
		t.Fatalf("got %s", hexs(got))
	}
	got = pbkdf2SHA256([]byte("password"), []byte("salt"), 4096, 32)
	want = "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
	if hexs(got) != want {
		t.Fatalf("got %s", hexs(got))
	}
}

func hexs(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, 0, len(b)*2)
	for _, c := range b {
		o = append(o, h[c>>4], h[c&15])
	}
	return string(o)
}

func TestTools(t *testing.T) {
	p, err := generatePassword(24, true)
	if err != nil || len(p) != 24 {
		t.Fatal("genpass failed")
	}
	s, _ := assessPassword("password")
	if s.Rating != "VERY WEAK" {
		t.Fatalf("expected VERY WEAK, got %s", s.Rating)
	}
	if r := identifyHash("5d41402abc4b2a76b9719d911017c592"); len(r) == 0 || r[0] != "MD5" {
		t.Fatal("identify failed")
	}
}
