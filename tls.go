package sni

import (
	"fmt"
	"io"
	"math"
)

const (
	byteLen = math.MaxUint8 + 1
)

// TLSHost returns the TLS host
func TLSHost(r io.Reader) (string, error) {
	var tmp [byteLen]byte
	err := skipExtensionBlock(r, tmp[:])
	if err != nil {
		return "", err
	}
	err = skipSN(r, tmp[:])
	if err != nil {
		return "", err
	}
	err = skipSNI(r, tmp[:])
	if err != nil {
		return "", err
	}
	_, err = io.ReadFull(r, tmp[:2])
	if err != nil {
		return "", err
	}
	blockLen := number(tmp[:2])
	_, err = io.ReadFull(r, tmp[:blockLen])
	if err != nil {
		return "", err
	}
	return string(tmp[:blockLen]), nil
}

// skipSNI skips the SNI block
func skipSNI(r io.Reader, tmp []byte) error {
	_, err := io.ReadFull(r, tmp[:2])
	if err != nil {
		return fmt.Errorf("SNI block: %w", err)
	}
	blockLength := number(tmp[:2])

	for length := 0; length < blockLength; {
		_, err = io.ReadFull(r, tmp[:3])
		if err != nil {
			return fmt.Errorf("SNI block: %w", err)
		}

		if tmp[2] == 0 {
			return nil
		}

		itemLength := number(tmp[:2]) - 1
		length += itemLength + 4
		for itemLength > 0 {
			n, err := io.ReadFull(r, tmp[:itemLength%len(tmp)])
			if err != nil {
				return fmt.Errorf("SNI block: %w", err)
			}
			itemLength -= n
		}
	}
	return fmt.Errorf("SNI was not found")
}

// skipSN skips the SN block
func skipSN(r io.Reader, tmp []byte) error {
	_, err := io.ReadFull(r, tmp[:2])
	if err != nil {
		return fmt.Errorf("SN block: %w", err)
	}

	blockLength := number(tmp[:2])

	for length := 0; length+4 < blockLength; {
		_, err = io.ReadFull(r, tmp[:2])
		if err != nil {
			return fmt.Errorf("SN block: %w", err)
		}

		if tmp[0] == 0 && tmp[1] == 0 {
			return nil
		}

		_, err = io.ReadFull(r, tmp[:2])
		if err != nil {
			return fmt.Errorf("SN block: %w", err)
		}

		itemLength := number(tmp[:2])
		length += itemLength + 4
		for itemLength > 0 {
			n, err := io.ReadFull(r, tmp[:itemLength%len(tmp)])
			if err != nil {
				return fmt.Errorf("SN block: %w", err)
			}
			itemLength -= n
		}
	}
	return fmt.Errorf("SN was not found")
}

// skipExtensionBlock skips the extension block
func skipExtensionBlock(r io.Reader, tmp []byte) error {
	const (
		totalLengthOffset = 5
		sessionIDOffset   = totalLengthOffset + 38
	)
	_, err := io.ReadFull(r, tmp[:sessionIDOffset+1])
	if err != nil {
		return fmt.Errorf("client hello: %w", err)
	}

	sessionIDLength := int(tmp[sessionIDOffset])

	_, err = io.ReadFull(r, tmp[:sessionIDLength+2])
	if err != nil {
		return fmt.Errorf("session id: %w", err)
	}

	cipherListLength := number(tmp[sessionIDLength:])
	for cipherListLength > len(tmp) {
		n, err := io.ReadFull(r, tmp[:])
		if err != nil {
			return fmt.Errorf("cipher list: %w", err)
		}
		cipherListLength -= n
	}
	_, err = io.ReadFull(r, tmp[:cipherListLength+1])
	if err != nil {
		return fmt.Errorf("cipher list: %w", err)
	}

	compressionLength := int(tmp[cipherListLength])

	_, err = io.ReadFull(r, tmp[:compressionLength])
	if err != nil {
		return fmt.Errorf("compression length: %w", err)
	}

	return nil
}

func number(data []byte) int {
	b1 := int(data[0])
	b2 := int(data[1])
	return (b1 << 8) + b2
}
