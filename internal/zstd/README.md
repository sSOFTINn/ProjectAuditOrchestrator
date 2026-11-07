# Vendored Go Zstandard decoder

The eight production Go files in this directory originate from Go 1.27.1
`src/internal/zstd` from the project's pinned and checksum-verified Go toolchain.
Upstream source: https://go.googlesource.com/go/+/refs/tags/go1.27.1/src/internal/zstd/
Copyright and BSD-3-Clause license headers are retained; `LICENSE` is the exact
Go 1.27.1 license. There is no new network module dependency.

PAO modifies `zstd.go`: it supports a declared history window up to 128 MiB
and rejects larger declarations before allocation, including single-segment
frames. The upstream 8 MiB clamp could not decode valid distant backreferences
in the official Grype database. PAO also modifies `bits.go` to split reverse
bitstream values wider than 24 bits into smaller reads: bytewise refill of a
26/27-bit offset could otherwise overflow its 32-bit accumulator. The other
six production files are unchanged.
Compressed-block and literal-section size checks remain in place; frame
checksums are still verified. Sequence expansion can temporarily exceed the
nominal block size before the decoder rejects it, so that size is not an exact
peak-allocation guarantee. The setup caller separately bounds total decoded
archive bytes.
`internal/setup` additionally applies compressed-byte, expanded-byte, per-member,
entry-count, path/type, context-cancellation and runtime limits. This decoder alone
is not an archive extractor or an authenticity verifier. The 128 MiB history
allocation is a fixed ceiling, not a value controlled without bounds by an
archive header. Larger windows require an explicit future compatibility change.

Exact SHA-256 of original upstream production sources (before PAO modification):
- bits.go: 6f9235b3e7827c80606e25f9b536ebe3c88b05eb2c366139404ce146ff516f57
- block.go: 7b0479fbe719c92a4112d6258c976fabbbab7c6b2cafab550f40d2e34727724f
- fse.go: 3e250ec2640ac73381b4689227bbb21c2610a280022714c68ff44666510a28d0
- huff.go: 5f7fbd4b3470b5620a46fd880e2a2a5530d9bdaa6d4b17afb0c24989484ae276
- literals.go: 24480c9f7fc20e05dcbefd3caea5487def845b0b07e48af90047da2932753cd0
- window.go: c0fbd759f898b724e239f5b6c672399a0ec8d3f2409c93c9ec861f2672893d44
- xxhash.go: f58eec158622514c6c98672b0e278712bb99c586bcd71ec42921e4c32c54b54b
- zstd.go: c67c7b243c4b4a2c769a1696130f378264ed86975c4c0bd1fc0df5ed81c061a2
