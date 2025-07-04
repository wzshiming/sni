package sni

import (
	"fmt"
	"io"
)

// TLSHost returns the TLS host
func TLSHost(r io.Reader) (string, error) {
	const (
		byteLen = 257
	)

	var data [byteLen]byte
	tmp := data[:]
	err := skipExtensionBlock(r, tmp)
	if err != nil {
		return "", fmt.Errorf("extension block: %w", err)
	}
	err = skipSN(r, tmp)
	if err != nil {
		return "", fmt.Errorf("SN block: %w", err)
	}
	err = skipSNI(r, tmp)
	if err != nil {
		return "", fmt.Errorf("SNI block: %w", err)
	}
	_, err = io.ReadFull(r, tmp[:2])
	if err != nil {
		return "", err
	}
	serverNameLen := number(tmp[:2])
	if serverNameLen <= 0 {
		return "", ErrNotFound
	}
	if serverNameLen > len(tmp) {
		return "", fmt.Errorf("server name too long: %d", serverNameLen)
	}
	_, err = io.ReadFull(r, tmp[:serverNameLen])
	if err != nil {
		return "", err
	}
	return string(tmp[:serverNameLen]), nil
}

// skipSNI skips the SNI block
func skipSNI(r io.Reader, tmp []byte) error {
	_, err := io.ReadFull(r, tmp[:2])
	if err != nil {
		return fmt.Errorf("failed to read SNI block length: %w", err)
	}
	blockLength := number(tmp[:2])
	for length := 0; length < blockLength; {
		_, err = io.ReadFull(r, tmp[:3])
		if err != nil {
			return fmt.Errorf("failed to read SNI block item: %w", err)
		}
		if tmp[2] == 0 {
			return nil
		}

		itemLength := number(tmp[:2]) - 1
		length += itemLength + 4
		err = skip(r, itemLength, tmp)
		if err != nil {
			return fmt.Errorf("failed to skip SNI block item data: %w", err)
		}
	}
	return ErrNotFound
}

// skipSN skips the SN block
func skipSN(r io.Reader, tmp []byte) error {
	_, err := io.ReadFull(r, tmp[:2])
	if err != nil {
		return fmt.Errorf("failed to read SN block: %w", err)
	}
	blockLength := number(tmp[:2])
	for length := 0; length+4 < blockLength; {
		_, err = io.ReadFull(r, tmp[:2])
		if err != nil {
			return fmt.Errorf("failed to read SN block item: %w", err)
		}
		if tmp[0] == 0 && tmp[1] == 0 {
			return nil
		}

		_, err = io.ReadFull(r, tmp[:2])
		if err != nil {
			return fmt.Errorf("failed to read SN block item length: %w", err)
		}

		itemLength := number(tmp[:2])
		length += itemLength + 4
		err = skip(r, itemLength, tmp)
		if err != nil {
			return fmt.Errorf("failed to skip SN block item data: %d %w", itemLength, err)
		}
	}
	return ErrNotFound
}

// skipExtensionBlock skips the extension block
func skipExtensionBlock(r io.Reader, tmp []byte) error {
	const (
		totalLengthOffset = 5
		sessionIDOffset   = totalLengthOffset + 38
	)

	n, err := io.ReadFull(r, tmp[:sessionIDOffset+1])
	if err != nil {
		return fmt.Errorf("client hello: %q: %w", tmp[:n], err)
	}
	if tmp[0] != 0x16 || tmp[1] != 0x03 {
		return fmt.Errorf("not a TLS handshake: %q", tmp[:n])
	}

	sessionIDLength := int(tmp[sessionIDOffset])
	_, err = io.ReadFull(r, tmp[:sessionIDLength+2])
	if err != nil {
		return fmt.Errorf("session id: %w", err)
	}

	cipherListLength := number(tmp[sessionIDLength:])
	if cipherListLength > len(tmp)-1 {
		return fmt.Errorf("cipher list too long: %d", cipherListLength)
	}
	err = skip(r, cipherListLength+1, tmp)
	if err != nil {
		return fmt.Errorf("cipher list: %w", err)
	}

	compressionLength := int(tmp[cipherListLength])
	err = skip(r, compressionLength, tmp)
	if err != nil {
		return fmt.Errorf("compression length: %w", err)
	}

	return nil
}

func skip(r io.Reader, n int, buf []byte) error {
	for n > 0 {
		chunkSize := n
		if chunkSize > len(buf) {
			chunkSize = len(buf)
		}
		m, err := io.ReadFull(r, buf[:chunkSize])
		if err != nil {
			return err
		}
		n -= m
	}
	return nil
}

func number(data []byte) int {
	b1 := int(data[0])
	b2 := int(data[1])
	return (b1 << 8) + b2
}
