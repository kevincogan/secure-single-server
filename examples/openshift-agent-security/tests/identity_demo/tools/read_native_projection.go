// SPDX-License-Identifier: Apache-2.0
// Operator diagnostic only: stdout contains a credential and must stay private.
package main

import (
	"fmt"
	"io"
	"os"
)

const projectionPath = "/var/run/secrets/openshell/token"
const maximumBytes = 65536

// copyProjection rejects empty or oversized input before writing any bytes.
func copyProjection(source io.Reader, destination io.Writer) error {
	data, err := io.ReadAll(io.LimitReader(source, maximumBytes+1))
	if err != nil || len(data) == 0 || len(data) > maximumBytes {
		return fmt.Errorf("projection read failed")
	}
	written, err := destination.Write(data)
	if err != nil || written != len(data) {
		return fmt.Errorf("projection write failed")
	}
	return nil
}

func main() {
	if len(os.Args) != 1 {
		os.Exit(2)
	}
	file, err := os.Open(projectionPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "projection read failed")
		os.Exit(1)
	}
	defer file.Close()
	if err := copyProjection(file, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "projection transfer failed")
		os.Exit(1)
	}
}
