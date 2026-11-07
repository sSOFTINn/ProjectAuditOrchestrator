package zstd

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestPAODistantReference(t *testing.T) {
	// Synthetic zstd 1.5.5 --long=27 -19 frame: a repeated SHA-256 marker,
	// 9 MiB of zeros, then the marker again. The final match reaches beyond
	// the upstream Go decoder's 8 MiB history. No database bytes are embedded.
	const fixture = "KLUv/QSIdAEAFALnv3tfJXIbAdh7fpq2A/cpqgYjbEn2nNO89gITygWG0AACAPz3bi7Q/fjVEwIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAdQAAAANAAN2DfwQAkvD+fxB8Ik0O"
	compressed, err := base64.StdEncoding.DecodeString(fixture)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	n, err := io.Copy(hash, NewReader(bytes.NewReader(compressed)))
	if err != nil || n != 9441280 || fmt.Sprintf("%x", hash.Sum(nil)) != "3036fc946c8853d72ad463555bc96acf66c80e68e18c7e5d80a179e57d33a3e4" {
		t.Fatalf("distant reference: bytes=%d sha256=%x err=%v", n, hash.Sum(nil), err)
	}
	compressed[len(compressed)-1] ^= 1
	if _, err := io.Copy(io.Discard, NewReader(bytes.NewReader(compressed))); err == nil || !strings.Contains(err.Error(), "invalid checksum") {
		t.Fatalf("corrupted checksum accepted: %v", err)
	}
}

func TestPAORawFrameAndInvalidBlocks(t *testing.T) {
	// Single-segment frame, five-byte raw final block, no dictionary/checksum.
	frame := []byte{0x28, 0xb5, 0x2f, 0xfd, 0x20, 5, 41, 0, 0, 'h', 'e', 'l', 'l', 'o'}
	raw, err := io.ReadAll(NewReader(bytes.NewReader(frame)))
	if err != nil || string(raw) != "hello" {
		t.Fatalf("raw frame: %q %v", raw, err)
	}
	for name, input := range map[string][]byte{
		"truncated":           frame[:len(frame)-1],
		"reserved block type": {0x28, 0xb5, 0x2f, 0xfd, 0x20, 1, 15, 0, 0, 'x'},
		"dictionary required": {0x28, 0xb5, 0x2f, 0xfd, 0x21, 1, 1, 9, 0, 0, 'x'},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := io.ReadAll(NewReader(bytes.NewReader(input))); err == nil {
				t.Fatal("invalid frame accepted")
			}
		})
	}
}

func TestPAOLargeDeclaredWindowIsBounded(t *testing.T) {
	for name, frame := range map[string][]byte{
		"256 MiB":        {0x28, 0xb5, 0x2f, 0xfd, 0, 0x90, 9, 0, 0, 'x'},
		"2 TiB":          {0x28, 0xb5, 0x2f, 0xfd, 0, 0xf8, 9, 0, 0, 'x'},
		"single segment": {0x28, 0xb5, 0x2f, 0xfd, 0xa0, 1, 0, 0, 8, 9, 0, 0, 'x'},
	} {
		t.Run(name, func(t *testing.T) {
			reader := NewReader(bytes.NewReader(frame))
			raw, err := io.ReadAll(reader)
			if err == nil || !strings.Contains(err.Error(), "window size exceeds 128 MiB limit") || len(raw) != 0 {
				t.Fatalf("oversized window accepted: %q %v", raw, err)
			}
			if cap(reader.window.data) != 0 || cap(reader.buffer) != 0 {
				t.Fatal("unsupported frame allocated a window or output block")
			}
		})
	}
}

func TestPAOWideReverseValuesAcrossByteAlignment(t *testing.T) {
	// Known bitstream with 0..7 initial payload bits before four data bytes.
	// A 25..31-bit value can cross a 32-bit refill boundary. Compare the
	// public bit-order result to a complete uint64 representation of input.
	for initial := uint8(0); initial < 8; initial++ {
		for width := uint8(25); width <= 31; width++ {
			data := block{0x6c, 0x13, 0xd7, 0xa5, byte((1 << (initial + 1)) - 1)}
			reader := NewReader(bytes.NewReader(nil))
			bits, err := reader.makeReverseBitReader(data, len(data)-1, 0)
			if err != nil {
				t.Fatal(err)
			}
			value, err := bits.val(width)
			whole := uint64((1<<initial)-1)<<32 | 0xa5d7136c
			want := uint32(whole >> (initial + 32 - width))
			if err != nil || value != want {
				t.Fatalf("initial=%d width=%d: got=%x want=%x err=%v", initial, width, value, want, err)
			}
		}
	}
}
