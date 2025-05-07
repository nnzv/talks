// Copyright 2024 Enzo Venturi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// This app is a basic tool to help learn about strace(1), focusing on the read(2)
// syscall. It continuously reads the hostname from /etc in a loop. You can edit
// the source code as needed.
//
//     CGO_ENABLED=0 go build -ldflags="-w -s" -o kcd
//     strace -e read ./kcd
//
//     read(3, "6b5f2bf7356b\n", 512)    = 13
//     read(3, "", 499)                  = 0
//     ...
//     read(3, "6b5f2bf7356b\n", 512)    = 13
//     read(3, "", 499)                  = 0
//
// By the way, what output might strace show if you run:
//
//     strace -e read go run main.go
//
// I'll leave that as a homework assignment.

package main

import "os"

func main() {
	for {
		_, err := os.ReadFile("/etc/hostname")
		// I usually avoid panic but am skipping extra imports.
		if err != nil {
			// https://go.dev/wiki/PanicAndRecover
			panic(err)
		}
	}
}
