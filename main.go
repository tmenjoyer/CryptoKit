// CryptoKit - a small cryptography & ethical-security command-line toolkit.
// Standard library only. For lawful, authorized and educational use.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const version = "1.0.0"

var stdin = bufio.NewReader(os.Stdin)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "encrypt":
		err = cmdCrypt(true, os.Args[2:])
	case "decrypt":
		err = cmdCrypt(false, os.Args[2:])
	case "hash":
		err = cmdHash(os.Args[2:])
	case "genpass":
		err = cmdGenpass(os.Args[2:])
	case "strength":
		err = cmdStrength(os.Args[2:])
	case "identify":
		err = cmdIdentify(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("CryptoKit", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`CryptoKit ` + version + ` - cryptography & ethical security toolkit

Usage:
  cryptokit <command> [options]

Commands:
  encrypt   Encrypt a file   (AES-256-GCM + PBKDF2-HMAC-SHA256)
  decrypt   Decrypt a file
  hash      Compute or verify a file/string hash
  genpass   Generate cryptographically secure passwords
  strength  Estimate password strength (entropy)
  identify  Guess the type of a hash from its format
  version   Print version

Run "cryptokit <command> -h" for command options.
Use only on data and systems you own or are authorized to test.
`)
}

// readPassword prompts without echo.
func readPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	restore := disableEcho()
	line, err := stdin.ReadString('\n')
	restore()
	fmt.Fprintln(os.Stderr)
	if err != nil && line == "" {
		return nil, err
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

func cmdCrypt(encrypt bool, args []string) error {
	name := "decrypt"
	if encrypt {
		name = "encrypt"
	}
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	out := fs.String("o", "", "output file (default: add/remove .ckit extension)")
	force := fs.Bool("f", false, "overwrite output file if it exists")
	iters := fs.Int("iter", defaultIters, "PBKDF2 iterations (encrypt only)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: cryptokit %s [-o output] [-f] <file>\n", name)
		fmt.Fprintln(os.Stderr, "Password: prompted securely, or taken from env CRYPTOKIT_PASSWORD.")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("exactly one input file is required")
	}
	in := fs.Arg(0)

	if *out == "" {
		if encrypt {
			*out = in + ".ckit"
		} else if strings.HasSuffix(in, ".ckit") {
			*out = strings.TrimSuffix(in, ".ckit")
		} else {
			*out = in + ".dec"
		}
	}
	if sameFile(in, *out) {
		return errors.New("input and output must be different files")
	}
	if _, err := os.Stat(*out); err == nil && !*force {
		return fmt.Errorf("%s already exists (use -f to overwrite)", *out)
	}

	pw := []byte(os.Getenv("CRYPTOKIT_PASSWORD"))
	if len(pw) == 0 {
		var err error
		pw, err = readPassword("Password: ")
		if err != nil {
			return err
		}
		if encrypt {
			confirm, err := readPassword("Confirm password: ")
			if err != nil {
				return err
			}
			if string(pw) != string(confirm) {
				return errors.New("passwords do not match")
			}
		}
	}
	if len(pw) == 0 {
		return errors.New("empty password")
	}
	if encrypt && *iters < 100_000 {
		return errors.New("-iter must be at least 100000")
	}

	src, err := os.Open(in)
	if err != nil {
		return err
	}
	defer src.Close()

	tmp, err := os.CreateTemp(filepath.Dir(*out), ".cryptokit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename

	bw := bufio.NewWriter(tmp)
	if encrypt {
		err = encryptStream(src, bw, pw, *iters)
	} else {
		err = decryptStream(src, bw, pw)
	}
	if err == nil {
		err = bw.Flush()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmpName, *out); err != nil {
		if *force {
			os.Remove(*out)
			if err = os.Rename(tmpName, *out); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	fmt.Printf("%sed %s -> %s\n", name, in, *out)
	return nil
}

func sameFile(a, b string) bool {
	ai, err1 := os.Stat(a)
	bi, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(ai, bi)
}

func cmdHash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	algo := fs.String("a", "sha256", "algorithm: md5, sha1, sha256, sha384, sha512")
	str := fs.String("s", "", "hash this string instead of a file")
	check := fs.String("c", "", "expected hash to compare against")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: cryptokit hash [-a algo] [-c expected] (-s string | file | -)")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	var r io.Reader
	label := ""
	switch {
	case *str != "":
		r = strings.NewReader(*str)
		label = "(string)"
	case fs.NArg() == 1 && fs.Arg(0) == "-":
		r = os.Stdin
		label = "(stdin)"
	case fs.NArg() == 1:
		f, err := os.Open(fs.Arg(0))
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
		label = fs.Arg(0)
	default:
		fs.Usage()
		return errors.New("provide a file, '-', or -s <string>")
	}

	sum, err := hashReader(r, *algo)
	if err != nil {
		return err
	}
	fmt.Printf("%s  %s  %s\n", strings.ToUpper(*algo), sum, label)
	if *check != "" {
		if strings.EqualFold(strings.TrimSpace(*check), sum) {
			fmt.Println("MATCH: hash is identical.")
			return nil
		}
		return errors.New("MISMATCH: hash differs from expected value")
	}
	return nil
}

func cmdGenpass(args []string) error {
	fs := flag.NewFlagSet("genpass", flag.ExitOnError)
	length := fs.Int("l", 20, "password length")
	count := fs.Int("n", 1, "number of passwords")
	noSym := fs.Bool("no-symbols", false, "exclude symbols")
	fs.Parse(args)
	if *count < 1 || *count > 1000 {
		return errors.New("-n must be between 1 and 1000")
	}
	for i := 0; i < *count; i++ {
		p, err := generatePassword(*length, !*noSym)
		if err != nil {
			return err
		}
		fmt.Println(p)
	}
	return nil
}

func cmdStrength(args []string) error {
	fs := flag.NewFlagSet("strength", flag.ExitOnError)
	fs.Parse(args)
	var pw string
	if fs.NArg() == 1 {
		pw = fs.Arg(0)
	} else {
		b, err := readPassword("Password to evaluate: ")
		if err != nil {
			return err
		}
		pw = string(b)
	}
	s, err := assessPassword(pw)
	if err != nil {
		return err
	}
	fmt.Printf("Estimated entropy: %.1f bits\nRating: %s\n", s.Entropy, s.Rating)
	for _, n := range s.Notes {
		fmt.Println(" - " + n)
	}
	return nil
}

func cmdIdentify(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: cryptokit identify <hash>")
	}
	res := identifyHash(args[0])
	if len(res) == 0 {
		fmt.Println("Unknown or unsupported hash format.")
		return nil
	}
	fmt.Println("Possible types:", strings.Join(res, ", "))
	return nil
}
