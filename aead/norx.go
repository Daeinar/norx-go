/*
    norx.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package aead

const (
    NORX_W = 64              // wordsize
    NORX_R = 4               // number of rounds
    NORX_D = 1               // parallelism degree
    NORX_A = NORX_W * 4      // tag size
    NORX_N = NORX_W * 2      // nonce size
    NORX_K = NORX_W * 4      // key size
    NORX_B = NORX_W * 16     // state size
    NORX_C = NORX_W * 6      // capacity size
    RATE = NORX_B - NORX_C   // rate size
    HEADER_TAG  = 1 << 0
    PAYLOAD_TAG = 1 << 1
    TRAILER_TAG = 1 << 2
    FINAL_TAG   = 1 << 3
    BRANCH_TAG  = 1 << 4
    MERGE_TAG   = 1 << 5
    R0, R1, R2, R3 = 8, 19, 40, 63 // rotation offsets
    u0, u1 = 0x243F6A8885A308D3, 0x13198A2E03707344
    u2, u3 = 0xA4093822299F31D0, 0x082EFA98EC4E6C89
    u4, u5 = 0xAE8858DC339325A1, 0x670A134EE52D7FA6
    u6, u7 = 0xC4316D80CD967541, 0xD21DFBF8B630B762
    u8, u9 = 0x375A18D261E7F892, 0x343D1F187D92285B
)


type state_t struct {
    s [16]uint64
}


func ROTR(x,c uint64) uint64 {
    return (x >> c | x << (NORX_W - c))
}


func H(x,y uint64) uint64 {
    return (x ^ y) ^ ((x & y) << 1)
}


func G(a,b,c,d uint64) (uint64,uint64,uint64,uint64) {

    a = H(a,b)
    d = ROTR(a ^ d, R0)
    c = H(c,d)
    b = ROTR(b ^ c, R1)
    a = H(a,b)
    d = ROTR(a ^ d, R2)
    c = H(c,d)
    b = ROTR(b ^ c, R3)
    return a,b,c,d
}


func F(s []uint64) {
    // Column step
    s[ 0], s[ 4], s[ 8], s[12] = G(s[ 0], s[ 4], s[ 8], s[12])
    s[ 1], s[ 5], s[ 9], s[13] = G(s[ 1], s[ 5], s[ 9], s[13])
    s[ 2], s[ 6], s[10], s[14] = G(s[ 2], s[ 6], s[10], s[14])
    s[ 3], s[ 7], s[11], s[15] = G(s[ 3], s[ 7], s[11], s[15])
    // Diagonal step
    s[ 0], s[ 5], s[10], s[15] = G(s[ 0], s[ 5], s[10], s[15])
    s[ 1], s[ 6], s[11], s[12] = G(s[ 1], s[ 6], s[11], s[12])
    s[ 2], s[ 7], s[ 8], s[13] = G(s[ 2], s[ 7], s[ 8], s[13])
    s[ 3], s[ 4], s[ 9], s[14] = G(s[ 3], s[ 4], s[ 9], s[14])
}


func permute(state *state_t) {
    s := state.s[:]
    for i:=0; i<NORX_R; i++ { F(s) }
}


func setup(state *state_t, k []uint8, n []uint8) {

    s := state.s[:]

    s[ 0] = u0
    s[ 1] = LOAD64(n[ 0: 8])
    s[ 2] = LOAD64(n[ 8:16])
    s[ 3] = u1

    s[ 4] = LOAD64(k[ 0: 8])
    s[ 5] = LOAD64(k[ 8:16])
    s[ 6] = LOAD64(k[16:24])
    s[ 7] = LOAD64(k[24:32])

    s[ 8] = u2
    s[ 9] = u3
    s[10] = u4
    s[11] = u5

    s[12] = u6
    s[13] = u7
    s[14] = u8
    s[15] = u9

    s[14] ^= (NORX_R << 26) | (NORX_D << 18) | (NORX_W << 10) | NORX_A
    permute(state)
}


func process_header(state *state_t, in []uint8, inlen uint64) {

    if inlen > 0 {
        lastblock := make([]uint8, BYTES64(RATE))
        i := uint64(0)
        n := BYTES64(RATE)
        for inlen >= n {
            absorb_block( state, in[n*i:n*(i+1)], HEADER_TAG )
            inlen -= n
            i++
        }
        pad(lastblock[:], in[n*i:], inlen)
        absorb_block(state, lastblock[:], HEADER_TAG)
        BURN8(lastblock[:], BYTES64(RATE))
    }
}


func encrypt_msg(state *state_t, out []uint8, in []uint8, inlen uint64) {

    if inlen > 0 {
        lastblock := make([]uint8, BYTES64(RATE))
        n := BYTES64(RATE)
        i := uint64(0)
        for inlen >= n {
            encrypt_block(state, out[n*i:n*(i+1)], in[n*i:n*(i+1)])
            inlen -= n
            i++
        }
        pad(lastblock[:], in[n*i:], inlen)
        encrypt_block(state, lastblock[:], lastblock[:])
        copy(out[n*i:n*i+inlen], lastblock[:])
        BURN8(lastblock[:], BYTES64(RATE))
    }
}


func decrypt_msg(state *state_t, out []uint8, in []uint8, inlen uint64) {

    if inlen > 0 {
        n := BYTES64(RATE)
        i := uint64(0)
        for inlen >= n {
            decrypt_block(state, out[n*i:n*(i+1)], in[n*i:n*(i+1)])
            inlen -= n
            i++
        }
        decrypt_lastblock(state, out[n*i:n*i+inlen], in[n*i:n*i+inlen], inlen)
    }
}


func process_trailer(state *state_t, in []uint8, inlen uint64) {

    if inlen > 0 {
        lastblock := make([]uint8, BYTES64(RATE))
        i := uint64(0)
        n := BYTES64(RATE)
        for inlen >= n {
            absorb_block(state, in[n*i:n*(i+1)], TRAILER_TAG)
            inlen -= n
            i++
        }
        pad(lastblock[:], in[n*i:], inlen)
        absorb_block(state, lastblock[:], HEADER_TAG)
        BURN8(lastblock[:], BYTES64(RATE))
    }
}


func output_tag(state *state_t, tag []uint8) {

    inject_tag(state, FINAL_TAG)
    permute(state)
    permute(state)

    s := state.s[:]
    lastblock := make([]uint8, BYTES64(RATE))
    b := BYTES64(NORX_W)
    for i:= uint64(0); i < WORDS64(RATE); i++ {
        STORE64(lastblock[b*i:b*(i+1)], s[i])
    }
    copy(tag[:], lastblock[:])
    BURN8(lastblock[:], BYTES64(RATE))
}


func verify_tag(tag1 []uint8, tag2 []uint8) int {

    acc := 0
    for i := uint64(0); i < BYTES64(NORX_A); i++ {
        acc |= int(tag1[i] ^ tag2[i])
    }
    return (((acc - 1) >> 8) & 1) - 1
}


func pad(out []uint8, in []uint8, inlen uint64) {

    copy(out[:],in[:inlen])
    out[inlen] = 0x01
    out[BYTES64(RATE) - 1] |= 0x80
}


func inject_tag(state *state_t, tag uint64) {
    s := state.s[:]
    s[15] ^= tag
}


func absorb_block(state *state_t, in []uint8, tag uint64) {

    inject_tag(state, tag)
    permute(state)

    s := state.s[:]
    b := BYTES64(NORX_W)
    for i:= uint64(0); i < WORDS64(RATE); i++ {
        s[i] ^= LOAD64(in[b*i:b*(i+1)])
    }
}


func encrypt_block(state *state_t, out []uint8, in []uint8) {

    inject_tag(state, PAYLOAD_TAG)
    permute(state)

    s := state.s[:]
    b := BYTES64(NORX_W)
    for i:= uint64(0); i < WORDS64(RATE); i++ {
        s[i] ^= LOAD64(in[b*i:b*(i+1)])
        STORE64(out[b*i:b*(i+1)], s[i])
    }
}


func decrypt_block(state *state_t, out []uint8, in []uint8) {

    inject_tag(state, PAYLOAD_TAG)
    permute(state)

    s := state.s[:]
    b := BYTES64(NORX_W)
    for i:= uint64(0); i < WORDS64(RATE); i++ {
        c := LOAD64(in[b*i:b*(i+1)])
        STORE64(out[b*i:b*(i+1)], s[i] ^ c)
        s[i] = c
    }
}


func decrypt_lastblock(state *state_t, out []uint8, in []uint8, inlen uint64) {

    inject_tag(state, PAYLOAD_TAG)
    permute(state)

    i := uint64(0)
    s := state.s[:]
    n := BYTES64(NORX_W)
    b := make([]uint8, n)

    /* undo padding */
    s[inlen / n] ^= uint64(0x01) << (inlen % n * 8)
    s[WORDS64(RATE) - 1] ^= uint64(0x80) << ((BYTES64(RATE) - 1) % n * 8)

    for inlen >= n {
        c := LOAD64(in[n*i:n*(i+1)])
        STORE64(out[n*i:n*(i+1)], s[i] ^ c)
        s[i] = c
        inlen -= n
        i++
    }

    STORE64(b,s[i])
    for j := uint64(0); j < inlen; j++ {
      c := in[n*i+j]
      out[n*i+j] = b[j] ^ c
      b[j] = c
    }
    s[i] = LOAD64(b)
    BURN8(b,n)
}


func AEAD_encrypt(
    c []uint8, clen *uint64,
    h []uint8, hlen uint64,
    m []uint8, mlen uint64,
    t []uint8, tlen uint64,
    nonce []uint8,
    key []uint8) {

    state := new(state_t)
    setup(state, key, nonce)
    process_header(state, h, hlen)
    encrypt_msg(state, c, m, mlen)
    process_trailer(state, t, tlen)
    output_tag(state, c[ mlen: ])
    *clen = mlen + BYTES64(NORX_A)
    BURN64(state.s[:], WORDS64(NORX_B))
}


func AEAD_decrypt(
    m []uint8, mlen *uint64,
    h []uint8, hlen uint64,
    c []uint8, clen uint64,
    t []uint8, tlen uint64,
    nonce []uint8,
    key []uint8) int {

    if clen < BYTES64(NORX_A) {
      return -1
    }
    result := -1
    tag := make([]uint8, NORX_A)
    state := new(state_t)
    setup(state, key, nonce)
    process_header(state, h, hlen)
    decrypt_msg(state, m, c, clen - BYTES64(NORX_A))
    process_trailer(state, t, tlen)
    output_tag(state, tag)
    *mlen = clen - BYTES64(NORX_A)
    result = verify_tag(c[clen - BYTES64(NORX_A):], tag)
    if result != 0 {
        BURN8(m, clen - BYTES64(NORX_A))
    }
    BURN64(state.s[:], WORDS64(NORX_B))
    return result
}

