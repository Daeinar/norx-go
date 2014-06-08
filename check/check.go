/*
    check.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package check

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

    fmt.Println("package check")
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
            if j % 7 == 0 && j != 0 {
                fmt.Println()
            }
            fmt.Printf("0x%02X, ", c[j])
        }
        fmt.Printf("\n")

        if i == wlen - 1 {
            fmt.Println("}")
        } else {
            fmt.Println()
        }
    }
    fmt.Println("return kat[i:j]\n}")
}


func Check() int {

    var wlen uint64 = 256
    var hlen uint64 = 256
    var tlen uint64 = 0
    var klen uint64 = 32
    var nlen uint64 = 16

    w := make([]uint8, wlen)
    h := make([]uint8, hlen)
    t := make([]uint8, tlen)
    k := make([]uint8, klen)
    n := make([]uint8, nlen)

    var i uint64

    for i = 0; i < wlen; i++ { w[i] = uint8(255 & (i*197 + 123)) }
    for i = 0; i < hlen; i++ { h[i] = uint8(255 & (i*193 + 123)) }
    for i = 0; i < klen; i++ { k[i] = uint8(255 & (i*191 + 123)) }
    for i = 0; i < nlen; i++ { n[i] = uint8(255 & (i*181 + 123)) }

    var kat uint64 = 0

    for i = 0; i < wlen; i++ {

        m := make([]uint8, 256)
        c := make([]uint8, 256 + 32)
        copy(m,w[:i+1])

        var clen uint64 = 0
        var mlen uint64 = i
        var hlen uint64 = i

        norx.AEAD_encrypt(c, &clen, h, hlen, m, mlen, t, tlen, n, k)
        if 0 != cmp(getkat(kat,kat+clen),c,clen) {
            fmt.Printf("fail at encrypt check: %d\n", i)
            return -1
        }

        m = make([]uint8, 256)
        mlen = 0

        if 0 != norx.AEAD_decrypt(m, &mlen, h, hlen, c, clen, t, tlen, n, k) {
            fmt.Printf("fail at decrypt check: %d\n", i)
            return -1
        }

        if 0 != cmp(w,m,mlen) {
            fmt.Printf("fail at msg check: %d\n", i)
            return -1
        }

        kat += clen
    }
    fmt.Println("ok")
    return 0
}


func cmp(a []uint8, b []uint8, len uint64) int {

    var i uint64

    for i = 0; i < len; i++ {
        if a[i] != b[i] {
          return -1
        }
    }
    return 0
}
