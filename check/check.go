/*
    check.go
    ------

    This file is part of the NORX Go reference implementation.

    :copyright: (c) 2014 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package check

import norx "github.com/daeinar/norx-go/aead"

import "fmt"

func Genkat() {

    wlen := uint64(256)
    hlen := uint64(256)
    tlen := uint64(0)
    klen := uint64(32)
    nlen := uint64(16)

    w := make([]uint8, wlen)
    h := make([]uint8, hlen)
    t := make([]uint8, tlen)
    k := make([]uint8, klen)
    n := make([]uint8, nlen)

    for i := uint64(0); i < wlen; i++ { w[i] = uint8(255 & (i*197 + 123)) }
    for i := uint64(0); i < hlen; i++ { h[i] = uint8(255 & (i*193 + 123)) }
    for i := uint64(0); i < klen; i++ { k[i] = uint8(255 & (i*191 + 123)) }
    for i := uint64(0); i < nlen; i++ { n[i] = uint8(255 & (i*181 + 123)) }

    fmt.Println("package check")
    fmt.Println("func getkat(i uint64, j uint64) []uint8 {")
    fmt.Println("kat := []uint8{")
    for i := uint64(0); i < wlen; i++ {

        m := make([]uint8, 256)
        c := make([]uint8, 256 + 32)
        copy(m,w[:i+1])

        clen := uint64(0)
        mlen := uint64(i)
        hlen := uint64(i)

        norx.AEAD_encrypt(c, &clen, h, hlen, m, mlen, t, tlen, n, k)

        norx.Print_bytes(c, clen)
        if i == wlen - 1 {
            fmt.Println("}")
        } else {
            fmt.Println()
        }
    }
    fmt.Println("return kat[i:j]\n}")
}


func Check() int {

    wlen := uint64(256)
    hlen := uint64(256)
    tlen := uint64(0)
    klen := uint64(32)
    nlen := uint64(16)

    w := make([]uint8, wlen)
    h := make([]uint8, hlen)
    t := make([]uint8, tlen)
    k := make([]uint8, klen)
    n := make([]uint8, nlen)

    for i := uint64(0); i < wlen; i++ { w[i] = uint8(255 & (i*197 + 123)) }
    for i := uint64(0); i < hlen; i++ { h[i] = uint8(255 & (i*193 + 123)) }
    for i := uint64(0); i < klen; i++ { k[i] = uint8(255 & (i*191 + 123)) }
    for i := uint64(0); i < nlen; i++ { n[i] = uint8(255 & (i*181 + 123)) }

    kat := uint64(0)

    for i := uint64(0); i < wlen; i++ {

        m := make([]uint8, 256)
        c := make([]uint8, 256 + 32)
        copy(m,w[:i+1])

        clen := uint64(0)
        mlen := uint64(i)
        hlen := uint64(i)

        norx.AEAD_encrypt(c, &clen, h, hlen, m, mlen, t, tlen, n, k)
        if 0 != cmp(getkat(kat,kat+clen),c,clen) {
            fmt.Printf("fail at encrypt check: %d\n", i)
            return -1
        }

        m = make([]uint8, 256)
        mlen = uint64(0)

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

    for i := uint64(0); i < len; i++ {
        if a[i] != b[i] {
          return -1
        }
    }
    return 0
}
