/*
    utils.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package aead

func LOAD64(x []uint8) uint64 {
    return (uint64(x[0]) <<  0) |
           (uint64(x[1]) <<  8) |
           (uint64(x[2]) << 16) |
           (uint64(x[3]) << 24) |
           (uint64(x[4]) << 32) |
           (uint64(x[5]) << 40) |
           (uint64(x[6]) << 48) |
           (uint64(x[7]) << 56)
}


func STORE64(out []uint8, v uint64) {
    out[0] = uint8(v >>  0);
    out[1] = uint8(v >>  8);
    out[2] = uint8(v >> 16);
    out[3] = uint8(v >> 24);
    out[4] = uint8(v >> 32);
    out[5] = uint8(v >> 40);
    out[6] = uint8(v >> 48);
    out[7] = uint8(v >> 56);
}


func BURN8(x []uint8, xlen uint64) {
    for i:= uint64(0); i < xlen; i++ {
        x[i] = 0
    }
}


func BURN64(x []uint64, xlen uint64) {
    for i:= uint64(0); i < xlen; i++ {
        x[i] = 0
    }
}

