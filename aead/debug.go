/*
    debug.go
    ------

    This file is part of the NORX Go reference implementation.

    :copyright: (c) 2014 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/


package aead

import "fmt"

func Print_state(s []uint64) {
    fmt.Printf("%016X %016X %016X %016X\n", s[ 0], s[ 1], s[ 2], s[ 3])
    fmt.Printf("%016X %016X %016X %016X\n", s[ 4], s[ 5], s[ 6], s[ 7])
    fmt.Printf("%016X %016X %016X %016X\n", s[ 8], s[ 9], s[10], s[11])
    fmt.Printf("%016X %016X %016X %016X\n", s[12], s[13], s[14], s[15])
    fmt.Printf("\n")
}

func Print_bytes(in []uint8, inlen uint64) {
    for i := uint64(0); i<inlen; i++ {
      if i % 7 == 0 && i != 0 {
        fmt.Println()
      }
      fmt.Printf("0x%02X, ", in[i])
    }
    fmt.Printf("\n")
}

