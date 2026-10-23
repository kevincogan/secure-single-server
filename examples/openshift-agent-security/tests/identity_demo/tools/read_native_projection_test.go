// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type failedReader struct{}

func (failedReader) Read([]byte) (int, error) { return 0, errors.New("synthetic") }

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("synthetic") }

type shortWriter struct{}

func (shortWriter) Write(value []byte) (int, error) { return len(value) - 1, nil }

func TestProjectionBounds(t *testing.T) {
	for _, length := range []int{0, 1, maximumBytes, maximumBytes + 1} {
		var output bytes.Buffer
		value := strings.Repeat("x", length)
		err := copyProjection(strings.NewReader(value), &output)
		if length > 0 && length <= maximumBytes {
			if err != nil || output.String() != value {
				t.Fatal("bounded synthetic data was not copied exactly")
			}
		} else if err == nil || output.Len() != 0 {
			t.Fatal("invalid input must be rejected before emitting bytes")
		}
	}
}

func TestProjectionErrors(t *testing.T) {
	var output bytes.Buffer
	if copyProjection(failedReader{}, &output) == nil || output.Len() != 0 {
		t.Fatal("read failure emitted data")
	}
	for _, writer := range []io.Writer{failedWriter{}, shortWriter{}} {
		if copyProjection(strings.NewReader("synthetic"), writer) == nil {
			t.Fatal("write failure was accepted")
		}
	}
}
