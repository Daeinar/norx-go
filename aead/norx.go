/*
    norx.go
    ------

    This file is part of the Go reference implementation of NORX.

    :version: v2.0
    :copyright: (c) 2014, 2015 Philipp Jovanovic <philipp@jovanovic.io>
    :license: CC0, see LICENSE
*/


package aead

const (
    NORX_W      = 64                       // wordsize
    NORX_L      = 4                        // number of rounds
    NORX_P      = 1                        // parallelism degree
    NORX_T      = NORX_W * 4               // tag size
    WORDS_RATE  = 12                       // number of words in the rate
    WORDS_STATE = 16                       // ... in the state
    BYTES_WORD  = NORX_W / 8               // number of bytes in a word
    BYTES_RATE  = WORDS_RATE * BYTES_WORD  // ... in the rate
    BYTES_TAG   = NORX_T / 8               // ... in the tag
    HEADER_TAG  = 0x01                     // domain separation constant for header
    PAYLOAD_TAG = 0x02                     // ... for payload
    TRAILER_TAG = 0x04                     // ... for trailer
    FINAL_TAG   = 0x08                     // ... for finalisation
    BRANCH_TAG  = 0x10                     // ... for branching
    MERGE_TAG   = 0x20                     // ... for merging
    R0, R1, R2, R3 = 8, 19, 40, 63         // rotation offsets
)

type norx_state_t struct {
    s [WORDS_STATE]uint64
}

func load64(in []uint8) uint64 {
    return (uint64(in[0]) <<  0) |
           (uint64(in[1]) <<  8) |
           (uint64(in[2]) << 16) |
           (uint64(in[3]) << 24) |
           (uint64(in[4]) << 32) |
           (uint64(in[5]) << 40) |
           (uint64(in[6]) << 48) |
           (uint64(in[7]) << 56)
}

func store64(out []uint8, in uint64) {
    out[0] = uint8(in >>  0)
    out[1] = uint8(in >>  8)
    out[2] = uint8(in >> 16)
    out[3] = uint8(in >> 24)
    out[4] = uint8(in >> 32)
    out[5] = uint8(in >> 40)
    out[6] = uint8(in >> 48)
    out[7] = uint8(in >> 56)
}

func burn8(x []uint8, xlen uint64) {
    for i := uint64(0); i < xlen; i++ {
        x[i] = 0
    }
}

func burn64(x []uint64, xlen uint64) {
    for i := uint64(0); i < xlen; i++ {
        x[i] = 0
    }
}

func rotr(x,c uint64) uint64 {
    return ((x >> c) | (x << (NORX_W - c)))
}

func h(x,y uint64) uint64 {
    return (x ^ y) ^ ((x & y) << 1)
}

func g(a,b,c,d uint64) (uint64,uint64,uint64,uint64) {

    a = h(a,b)
    d = rotr(a ^ d, R0)
    c = h(c,d)
    b = rotr(b ^ c, R1)
    a = h(a,b)
    d = rotr(a ^ d, R2)
    c = h(c,d)
    b = rotr(b ^ c, R3)
    return a,b,c,d
}

func f(s []uint64) {

    // Column step
    s[ 0], s[ 4], s[ 8], s[12] = g(s[ 0], s[ 4], s[ 8], s[12])
    s[ 1], s[ 5], s[ 9], s[13] = g(s[ 1], s[ 5], s[ 9], s[13])
    s[ 2], s[ 6], s[10], s[14] = g(s[ 2], s[ 6], s[10], s[14])
    s[ 3], s[ 7], s[11], s[15] = g(s[ 3], s[ 7], s[11], s[15])
    // Diagonal step
    s[ 0], s[ 5], s[10], s[15] = g(s[ 0], s[ 5], s[10], s[15])
    s[ 1], s[ 6], s[11], s[12] = g(s[ 1], s[ 6], s[11], s[12])
    s[ 2], s[ 7], s[ 8], s[13] = g(s[ 2], s[ 7], s[ 8], s[13])
    s[ 3], s[ 4], s[ 9], s[14] = g(s[ 3], s[ 4], s[ 9], s[14])
}

func norx_permute(state *norx_state_t) {

    var s = state.s[:]
    for i := uint64(0); i < NORX_L; i++ {
        f(s)
    }
}

func norx_init(state *norx_state_t, k []uint8, n []uint8) {

    var s = state.s[:]

    for i := uint64(0); i < WORDS_STATE; i++ {
        s[i] = i
    }

    f(s)
    f(s)

    s[ 0] = load64(n[ 0: 8])
    s[ 1] = load64(n[ 8:16])

    s[ 4] = load64(k[ 0: 8])
    s[ 5] = load64(k[ 8:16])
    s[ 6] = load64(k[16:24])
    s[ 7] = load64(k[24:32])

    s[12] ^= NORX_W
    s[13] ^= NORX_L
    s[14] ^= NORX_P
    s[15] ^= NORX_T

    norx_permute(state)
}

func norx_absorb_data(state *norx_state_t, in []uint8, inlen uint64, tag uint64) {

    if inlen > 0 {

        var i uint64 = 0
        const n uint64 = BYTES_RATE

        for i = 0; inlen >= n; inlen, i = inlen-n, i+1 {
            norx_absorb_block(state, in[n*i:n*(i+1)], tag)
        }
        norx_absorb_lastblock(state, in[n*i:n*i+inlen], inlen, tag)
    }
}

func norx_encrypt_data(state *norx_state_t, out []uint8, in []uint8, inlen uint64) {

    if inlen > 0 {

        var i uint64 = 0
        const n uint64 = BYTES_RATE

        for i = 0; inlen >= n; inlen, i = inlen-n, i+1 {
            norx_encrypt_block(state, out[n*i:n*(i+1)], in[n*i:n*(i+1)])
        }
        encrypt_lastblock(state, out[n*i:n*i+inlen], in[n*i:n*i+inlen], inlen)
    }
}

func norx_decrypt_data(state *norx_state_t, out []uint8, in []uint8, inlen uint64) {

    if inlen > 0 {

        var i uint64 = 0
        const n uint64 = BYTES_RATE

        for i = 0; inlen >= n; inlen, i = inlen-n, i+1 {
            norx_decrypt_block(state, out[n*i:n*(i+1)], in[n*i:n*(i+1)])
        }
        norx_decrypt_lastblock(state, out[n*i:n*i+inlen], in[n*i:n*i+inlen], inlen)
    }
}

func norx_output_tag(state *norx_state_t, tag []uint8) {

    state.s[15] ^= FINAL_TAG
    norx_permute(state)
    norx_permute(state)

    var s = state.s[:]
    var lastblock [BYTES_RATE]uint8
    const b uint64 = BYTES_WORD

    for i := uint64(0); i < WORDS_RATE; i++ {
        store64(lastblock[b*i:b*(i+1)], s[i])
    }
    copy(tag[:], lastblock[:])
    burn8(lastblock[:], BYTES_RATE)
}

func norx_verify_tag(tag1 []uint8, tag2 []uint8) int {

    var acc int = 0

    for i := uint64(0); i < BYTES_TAG; i++ {
        acc |= int(tag1[i] ^ tag2[i])
    }
    return (((acc - 1) >> 8) & 1) - 1
}

func norx_pad(out []uint8, in []uint8, inlen uint64) {

    copy(out[:],in[:inlen])
    out[inlen] = 0x01
    out[BYTES_RATE - 1] |= 0x80
}

func norx_absorb_block(state *norx_state_t, in []uint8, tag uint64) {

    state.s[15] ^= tag
    norx_permute(state)

    var s = state.s[:]
    const b uint64 = BYTES_WORD

    for i := uint64(0); i < WORDS_RATE; i++ {
        s[i] ^= load64(in[b*i:b*(i+1)])
    }
}

func norx_absorb_lastblock(state *norx_state_t, in []uint8, inlen uint64, tag uint64) {

    var lastblock [BYTES_RATE]uint8
    norx_pad(lastblock[:], in[:], inlen)
    norx_absorb_block(state, lastblock[:], tag)
    burn8(lastblock[:], BYTES_RATE)
}

func norx_encrypt_block(state *norx_state_t, out []uint8, in []uint8) {

    state.s[15] ^= PAYLOAD_TAG
    norx_permute(state)

    var s = state.s[:]
    const b uint64 = BYTES_WORD

    for i := uint64(0); i < WORDS_RATE; i++ {
        s[i] ^= load64(in[b*i:b*(i+1)])
        store64(out[b*i:b*(i+1)], s[i])
    }
}

func encrypt_lastblock(state *norx_state_t, out []uint8, in []uint8, inlen uint64) {

    var lastblock [BYTES_RATE]uint8
    norx_pad(lastblock[:], in[:], inlen)
    norx_encrypt_block(state, lastblock[:], lastblock[:])
    copy(out[:], lastblock[:])
    burn8(lastblock[:], BYTES_RATE)
}

func norx_decrypt_block(state *norx_state_t, out []uint8, in []uint8) {

    state.s[15] ^= PAYLOAD_TAG
    norx_permute(state)

    var s = state.s[:]
    const b uint64 = BYTES_WORD

    for i := uint64(0); i < WORDS_RATE; i++ {
        c := load64(in[b*i:b*(i+1)])
        store64(out[b*i:b*(i+1)], s[i] ^ c)
        s[i] = c
    }
}

func norx_decrypt_lastblock(state *norx_state_t, out []uint8, in []uint8, inlen uint64) {

    state.s[15] ^= PAYLOAD_TAG
    norx_permute(state)

    var s = state.s[:]
    const n uint64 = BYTES_WORD
    var lastblock [BYTES_RATE]uint8

    for i := uint64(0); i < WORDS_RATE; i++ {
        store64(lastblock[n*i:n*(i+1)],s[i])
    }
    copy(lastblock[:],in[:inlen])
    lastblock[inlen] ^= 0x01
    lastblock[BYTES_RATE - 1] ^= 0x80

    for i := uint64(0); i < WORDS_RATE; i++ {
        c := load64(lastblock[n*i:n*(i+1)])
        store64(lastblock[n*i:n*(i+1)], s[i] ^ c)
        s[i] = c
    }
    copy(out[:inlen],lastblock[:])
    burn8(lastblock[:],BYTES_RATE)
}

func AEAD_encrypt(
    c []uint8, clen *uint64,
    a []uint8, alen uint64,
    m []uint8, mlen uint64,
    z []uint8, zlen uint64,
    nonce []uint8,
    key []uint8) {

    var state = new(norx_state_t)
    norx_init(state, key, nonce)
    norx_absorb_data(state, a, alen, HEADER_TAG)
    norx_encrypt_data(state, c, m, mlen)
    norx_absorb_data(state, z, zlen, TRAILER_TAG)
    norx_output_tag(state, c[mlen:])
    *clen = mlen + BYTES_TAG
    burn64(state.s[:], WORDS_STATE)
}

func AEAD_decrypt(
    m []uint8, mlen *uint64,
    a []uint8, alen uint64,
    c []uint8, clen uint64,
    z []uint8, zlen uint64,
    nonce []uint8,
    key []uint8) int {

    if clen < BYTES_TAG {
      return -1
    }
    var result int = -1
    var tag [BYTES_TAG]uint8
    var state = new(norx_state_t)
    norx_init(state, key, nonce)
    norx_absorb_data(state, a, alen, HEADER_TAG)
    norx_decrypt_data(state, m, c, clen - BYTES_TAG)
    norx_absorb_data(state, z, zlen, TRAILER_TAG)
    norx_output_tag(state, tag[:])
    *mlen = clen - BYTES_TAG
    result = norx_verify_tag(c[clen - BYTES_TAG:], tag[:])
    if result != 0 {
        burn8(m[:], clen - BYTES_TAG)
    }
    burn64(state.s[:], WORDS_STATE)
    return result
}

