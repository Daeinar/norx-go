/*
    norx.go
    ------

    This file is part of the Go reference implementation of NORX.

    :copyright: (c) 2014, 2015 Philipp Jovanovic <philipp@jovanovic.io>
    :license: BSD (3-Clause), see LICENSE
*/

package aead

const (
    NORX_W      = 64                                // wordsize
    NORX_R      = 4                                 // number of rounds
    NORX_D      = 1                                 // parallelism degree
    NORX_A      = NORX_W * 4                        // tag size
    WORDS_RATE  = 10                                // number of words in the rate
    WORDS_STATE = 16                                // ... in the state
    BYTES_WORD  = NORX_W / 8                        // byte size of a word
    BYTES_RATE  = WORDS_RATE * BYTES_WORD           // ... of the rate
    BYTES_TAG   = NORX_A / 8                        // ... of the tag
    HEADER_TAG  = 1 << 0                            // domain separation constant for header
    PAYLOAD_TAG = 1 << 1                            // ... for payload
    TRAILER_TAG = 1 << 2                            // ... for trailer
    FINAL_TAG   = 1 << 3                            // ... for finalisation
    BRANCH_TAG  = 1 << 4                            // ... for branching
    MERGE_TAG   = 1 << 5                            // ... for merging
    R0, R1, R2, R3 = 8, 19, 40, 63                  // rotation offsets
    U0, U1 = 0x243F6A8885A308D3, 0x13198A2E03707344 // initialisation constants
    U2, U3 = 0xA4093822299F31D0, 0x082EFA98EC4E6C89 // ...
    U4, U5 = 0xAE8858DC339325A1, 0x670A134EE52D7FA6 // ...
    U6, U7 = 0xC4316D80CD967541, 0xD21DFBF8B630B762 // ...
    U8, U9 = 0x375A18D261E7F892, 0x343D1F187D92285B // ...
)


type state_t struct {
    s [WORDS_STATE]uint64
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

    var s = state.s[:]
    for i := 0; i < NORX_R; i++ { F(s) }
}


func setup(state *state_t, k []uint8, n []uint8) {

    var s = state.s[:]

    s[ 0] = U0
    s[ 1] = LOAD64(n[ 0: 8])
    s[ 2] = LOAD64(n[ 8:16])
    s[ 3] = U1

    s[ 4] = LOAD64(k[ 0: 8])
    s[ 5] = LOAD64(k[ 8:16])
    s[ 6] = LOAD64(k[16:24])
    s[ 7] = LOAD64(k[24:32])

    s[ 8] = U2
    s[ 9] = U3
    s[10] = U4
    s[11] = U5

    s[12] = U6
    s[13] = U7
    s[14] = U8
    s[15] = U9

    s[12] ^= NORX_W
    s[13] ^= NORX_R
    s[14] ^= NORX_D
    s[15] ^= NORX_A

    permute(state)
}


func process_header(state *state_t, in []uint8, inlen uint64) {

    if inlen > 0 {

        var i uint64 = 0
        var n uint64 = BYTES_RATE

        for inlen >= n {
            absorb_block(state, in[n*i:n*(i+1)], HEADER_TAG)
            inlen -= n
            i++
        }
        absorb_lastblock(state, in[n*i:n*i+inlen], inlen, HEADER_TAG)
    }
}


func encrypt_msg(state *state_t, out []uint8, in []uint8, inlen uint64) {

    if inlen > 0 {

        var i uint64 = 0
        var n uint64 = BYTES_RATE

        for inlen >= n {
            encrypt_block(state, out[n*i:n*(i+1)], in[n*i:n*(i+1)])
            inlen -= n
            i++
        }
        encrypt_lastblock(state, out[n*i:n*i+inlen], in[n*i:n*i+inlen], inlen)
    }
}


func decrypt_msg(state *state_t, out []uint8, in []uint8, inlen uint64) {

    if inlen > 0 {

        var i uint64 = 0
        var n uint64 = BYTES_RATE

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

        var i uint64 = 0
        var n uint64 = BYTES_RATE

        for inlen >= n {
            absorb_block(state, in[n*i:n*(i+1)], TRAILER_TAG)
            inlen -= n
            i++
        }
        absorb_lastblock(state, in[n*i:n*i+inlen], inlen, TRAILER_TAG)
    }
}


func output_tag(state *state_t, tag []uint8) {

    inject_tag(state, FINAL_TAG)
    permute(state)
    permute(state)

    var s = state.s[:]
    var lastblock [BYTES_RATE]uint8
    var b uint64 = BYTES_WORD
    var i uint64

    for i = 0; i < WORDS_RATE; i++ {
        STORE64(lastblock[b*i:b*(i+1)], s[i])
    }
    copy(tag[:], lastblock[:])
    BURN8(lastblock[:], BYTES_RATE)
}


func verify_tag(tag1 []uint8, tag2 []uint8) int {

    var acc int = 0
    var i uint64

    for i = 0; i < BYTES_TAG; i++ {
        acc |= int(tag1[i] ^ tag2[i])
    }
    return (((acc - 1) >> 8) & 1) - 1
}


func pad(out []uint8, in []uint8, inlen uint64) {

    copy(out[:],in[:inlen])
    out[inlen] = 0x01
    out[BYTES_RATE - 1] |= 0x80
}


func inject_tag(state *state_t, tag uint64) {

    var s = state.s[:]
    s[15] ^= tag
}


func absorb_block(state *state_t, in []uint8, tag uint64) {

    inject_tag(state, tag)
    permute(state)

    var s = state.s[:]
    var b uint64 = BYTES_WORD
    var i uint64

    for i = 0; i < WORDS_RATE; i++ {
        s[i] ^= LOAD64(in[b*i:b*(i+1)])
    }
}


func absorb_lastblock(state *state_t, in []uint8, inlen uint64, tag uint64) {

    var lastblock [BYTES_RATE]uint8
    pad(lastblock[:], in[:], inlen)
    absorb_block(state, lastblock[:], tag)
    BURN8(lastblock[:], BYTES_RATE)
}


func encrypt_block(state *state_t, out []uint8, in []uint8) {

    inject_tag(state, PAYLOAD_TAG)
    permute(state)

    var s = state.s[:]
    var b uint64 = BYTES_WORD
    var i uint64

    for i = 0; i < WORDS_RATE; i++ {
        s[i] ^= LOAD64(in[b*i:b*(i+1)])
        STORE64(out[b*i:b*(i+1)], s[i])
    }
}


func encrypt_lastblock(state *state_t, out []uint8, in []uint8, inlen uint64) {

    var lastblock [BYTES_RATE]uint8
    pad(lastblock[:], in[:], inlen)
    encrypt_block(state, lastblock[:], lastblock[:])
    copy(out[:], lastblock[:])
    BURN8(lastblock[:], BYTES_RATE)
}


func decrypt_block(state *state_t, out []uint8, in []uint8) {

    inject_tag(state, PAYLOAD_TAG)
    permute(state)

    var s = state.s[:]
    var b uint64 = BYTES_WORD
    var i uint64

    for i = 0; i < WORDS_RATE; i++ {
        c := LOAD64(in[b*i:b*(i+1)])
        STORE64(out[b*i:b*(i+1)], s[i] ^ c)
        s[i] = c
    }
}


func decrypt_lastblock(state *state_t, out []uint8, in []uint8, inlen uint64) {

    inject_tag(state, PAYLOAD_TAG)
    permute(state)

    var s = state.s[:]
    var n uint64 = BYTES_WORD
    var lastblock [BYTES_RATE]uint8
    var i uint64

    for i = 0; i < WORDS_RATE; i++ {
        STORE64(lastblock[n*i:n*(i+1)],s[i])
    }
    copy(lastblock[:],in[:inlen])
    lastblock[inlen] ^= 0x01
    lastblock[BYTES_RATE - 1] ^= 0x80

    for i = 0; i < WORDS_RATE; i++ {
        c := LOAD64(lastblock[n*i:n*(i+1)])
        STORE64(lastblock[n*i:n*(i+1)], s[i] ^ c)
        s[i] = c
    }
    copy(out[:inlen],lastblock[:])
    BURN8(lastblock[:],BYTES_RATE)
}


func AEAD_encrypt(
    c []uint8, clen *uint64,
    h []uint8, hlen uint64,
    m []uint8, mlen uint64,
    t []uint8, tlen uint64,
    nonce []uint8,
    key []uint8) {

    var state = new(state_t)
    setup(state, key, nonce)
    process_header(state, h, hlen)
    encrypt_msg(state, c, m, mlen)
    process_trailer(state, t, tlen)
    output_tag(state, c[mlen:])
    *clen = mlen + BYTES_TAG
    BURN64(state.s[:], WORDS_STATE)
}


func AEAD_decrypt(
    m []uint8, mlen *uint64,
    h []uint8, hlen uint64,
    c []uint8, clen uint64,
    t []uint8, tlen uint64,
    nonce []uint8,
    key []uint8) int {

    if clen < BYTES_TAG {
      return -1
    }
    var result int = -1
    var tag [BYTES_TAG]uint8
    var state = new(state_t)
    setup(state, key, nonce)
    process_header(state, h, hlen)
    decrypt_msg(state, m, c, clen - BYTES_TAG)
    process_trailer(state, t, tlen)
    output_tag(state, tag[:])
    *mlen = clen - BYTES_TAG
    result = verify_tag(c[clen - BYTES_TAG:], tag[:])
    if result != 0 {
        BURN8(m[:], clen - BYTES_TAG)
    }
    BURN64(state.s[:], WORDS_STATE)
    return result
}

