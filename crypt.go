package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// File format (all integers big-endian):
//
//	magic       5 bytes   "CKIT1"
//	iterations  4 bytes   PBKDF2 iteration count
//	salt       16 bytes   random
//	noncePrefix 8 bytes   random
//	chunks...             each: AES-256-GCM(plaintext chunk <= 64 KiB) + 16-byte tag
//
// Chunk nonce  = noncePrefix || chunkIndex (4 bytes).
// Chunk AAD    = header || finalFlag (1 byte). The final flag defeats truncation.
const (
	magic        = "CKIT1"
	saltLen      = 16
	noncePfxLen  = 8
	chunkSize    = 64 * 1024
	tagLen       = 16
	keyLen       = 32
	defaultIters = 600_000
	headerLen    = len(magic) + 4 + saltLen + noncePfxLen
)

var errAuth = errors.New("authentication failed: wrong password or corrupted/tampered file")

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func chunkNonce(prefix []byte, idx uint32) []byte {
	n := make([]byte, 12)
	copy(n, prefix)
	binary.BigEndian.PutUint32(n[8:], idx)
	return n
}

func aadFor(header []byte, final bool) []byte {
	aad := make([]byte, len(header)+1)
	copy(aad, header)
	if final {
		aad[len(header)] = 1
	}
	return aad
}

// encryptStream encrypts r into w using a key derived from password.
func encryptStream(r io.Reader, w io.Writer, password []byte, iters int) error {
	salt := make([]byte, saltLen)
	prefix := make([]byte, noncePfxLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(prefix); err != nil {
		return err
	}

	header := make([]byte, 0, headerLen)
	header = append(header, magic...)
	header = binary.BigEndian.AppendUint32(header, uint32(iters))
	header = append(header, salt...)
	header = append(header, prefix...)
	if _, err := w.Write(header); err != nil {
		return err
	}

	gcm, err := newGCM(pbkdf2SHA256(password, salt, iters, keyLen))
	if err != nil {
		return err
	}

	br := bufio.NewReaderSize(r, chunkSize+1)
	buf := make([]byte, chunkSize)
	var idx uint32
	for {
		n, err := io.ReadFull(br, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		final := false
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			final = true
		} else if _, perr := br.Peek(1); perr == io.EOF {
			final = true
		}
		sealed := gcm.Seal(nil, chunkNonce(prefix, idx), buf[:n], aadFor(header, final))
		if _, werr := w.Write(sealed); werr != nil {
			return werr
		}
		if final {
			return nil
		}
		idx++
		if idx == 0 {
			return errors.New("file too large")
		}
	}
}

// decryptStream decrypts r into w using password.
func decryptStream(r io.Reader, w io.Writer, password []byte) error {
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(r, header); err != nil {
		return errors.New("file too short or not a CryptoKit file")
	}
	if !bytes.Equal(header[:len(magic)], []byte(magic)) {
		return errors.New("not a CryptoKit file (bad magic header)")
	}
	iters := int(binary.BigEndian.Uint32(header[len(magic):]))
	if iters < 1 || iters > 50_000_000 {
		return fmt.Errorf("invalid iteration count in header: %d", iters)
	}
	off := len(magic) + 4
	salt := header[off : off+saltLen]
	prefix := header[off+saltLen:]

	gcm, err := newGCM(pbkdf2SHA256(password, salt, iters, keyLen))
	if err != nil {
		return err
	}

	br := bufio.NewReaderSize(r, chunkSize+tagLen+1)
	buf := make([]byte, chunkSize+tagLen)
	var idx uint32
	for {
		n, err := io.ReadFull(br, buf)
		if err == io.EOF && idx > 0 {
			return errors.New("file truncated")
		}
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		final := false
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			final = true
		} else if _, perr := br.Peek(1); perr == io.EOF {
			final = true
		}
		if n < tagLen {
			return errors.New("file truncated or corrupted")
		}
		plain, oerr := gcm.Open(nil, chunkNonce(prefix, idx), buf[:n], aadFor(header, final))
		if oerr != nil {
			return errAuth
		}
		if _, werr := w.Write(plain); werr != nil {
			return werr
		}
		if final {
			return nil
		}
		idx++
	}
}
