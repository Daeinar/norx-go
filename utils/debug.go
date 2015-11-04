/*
    debug.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014, 2015 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package utils

import norx "github.com/daeinar/norx-go/aead"

import "fmt"

func print_bytes(in []uint8) {

    for i := 0; i < len(in); i++ {
        fmt.Printf("%02X ", in[i])
        if i % 16 == 15 {
            fmt.Printf("\n")
        }
    }
}

func Debug() {

    var alen uint64 = 128
    var mlen uint64 = 128
    var clen uint64 = 0
    var zlen uint64 = 128

    k := [32]uint8{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,
                   0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F}
    n := [16]uint8{0xF0,0xE0,0xD0,0xC0,0xB0,0xA0,0x90,0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10,0x00}
    a := make([]uint8, alen)
    m := make([]uint8, mlen)
    c := make([]uint8, mlen + 32)
    z := make([]uint8, zlen)

    var i uint64

    for i = 0; i < alen; i++ { a[i] = uint8(i & 255) }
    for i = 0; i < mlen; i++ { m[i] = uint8(i & 255) }
    for i = 0; i < zlen; i++ { z[i] = uint8(i & 255) }

    fmt.Printf("========== SETUP ==========\n")
    fmt.Printf("Key:\n")
    print_bytes(k[:])
    fmt.Printf("Nonce:\n")
    print_bytes(n[:])
    fmt.Printf("Header:\n")
    print_bytes(a[:])
    fmt.Printf("Message:\n")
    print_bytes(m[:])
    fmt.Printf("Trailer:\n")
    print_bytes(z[:])

    fmt.Printf("========== ENCRYPTION ==========\n")
    norx.AEAD_encrypt(c, &clen, a, alen, m, mlen, z, zlen, n[:], k[:])
    fmt.Printf("Ciphertext + tag:\n")
    print_bytes(c[:])

    m = make([]uint8, mlen)
    mlen = 0

    fmt.Printf("========== DECRYPTION ==========\n")
    result := norx.AEAD_decrypt(m, &mlen, a, alen, c, clen, z, zlen, n[:], k[:])
    fmt.Printf("Decrypted message:\n")
    print_bytes(m[:])

    fmt.Printf("verify: %d\n", result)
}
