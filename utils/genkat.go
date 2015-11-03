/*
    genkat.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014, 2015 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package utils

import norx "github.com/daeinar/norx-go/aead"

import "fmt"

func Genkat() {

    var wlen uint64 = 256
    var hlen uint64 = 256
    var tlen uint64 = 0
    var klen uint64 = 32
    var nlen uint64 = 16

    var w = make([]uint8, wlen)
    var h = make([]uint8, hlen)
    var t = make([]uint8, tlen)
    var k = make([]uint8, klen)
    var n = make([]uint8, nlen)

    var i,j uint64

    for i = 0; i < wlen; i++ { w[i] = uint8(255 & (i*197 + 123)) }
    for i = 0; i < hlen; i++ { h[i] = uint8(255 & (i*193 + 123)) }
    for i = 0; i < klen; i++ { k[i] = uint8(255 & (i*191 + 123)) }
    for i = 0; i < nlen; i++ { n[i] = uint8(255 & (i*181 + 123)) }

    fmt.Println("package utils")
    fmt.Println("func getkat(i uint64, j uint64) []uint8 {")
    fmt.Println("kat := []uint8{")
    for i = 0; i < wlen; i++ {

        m := make([]uint8, 256)
        c := make([]uint8, 256 + 32)
        copy(m,w[:i+1])

        var clen uint64 = 0
        var mlen uint64 = i
        var hlen uint64 = i

        norx.AEAD_encrypt(c, &clen, h, hlen, m, mlen, t, tlen, n, k)

        for j = 0; j < clen; j++ {
            fmt.Printf("0x%02X, ", c[j])
            if j % 8 == 7 || j == clen - 1 {
                fmt.Println()
            }
        }
        fmt.Println()

        if i == wlen - 1 {
            fmt.Println("}")
        }
    }
    fmt.Println("return kat[i:j]\n}")
}
