# ITB Crystal Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`), written against Crystal's native `lib` / `fun` C
bindings — no external shard dependencies, no C glue code. The
compiled binaries link `libitb.so` directly, and every hash-name /
MAC-name / cipher-name / profile-name is an opaque string passed
through to Go for validation — the binding carries no ITB construction
logic. The public surface is the `ITB::Pipeline` class (init / open /
rekey / close, Single Message encrypt / decrypt, whole-buffer and
incremental stream sessions), the fluent `ITB::Opts` query-string
builder, `ITB.register_profile`, the registry roster helpers, and the
Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go crystal shards
```

Generic Linux: any Crystal 1.x toolchain works. `shards` is only
needed for consuming the binding as a shard dependency — the in-repo
build, tests, and benches call the `crystal` compiler directly.

## Build

The convenience driver builds `libitb.so` (only when absent — set
`ITB_REBUILD_LIBITB=1` to force a Go rebuild) and compiles the eitb
CLI binary in one step:

```bash
./bindings/crystal/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/crystal && crystal build -o bin/eitb eitb/itb_eitb.cr
```

Hosts without AVX-512+VL: pass `--noitbasm` to `build.sh` to opt out
of ITB's chain-absorb asm.

## Library resolution

Linking is resolved at **compile time** through the
`@[Link(ldflags: ...)]` annotation in `src/itb/ffi_bridge.cr`, which
executes `src/itb/libitb_flags.sh`. Search order:

1. `ITB_LIBITB_PATH` environment variable (path to the shared library
   file) — read when the Crystal program is compiled.
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up from
   the binding source directory (in-repo builds).
3. The OS default loader path (`-litb`).

The resolved directory is baked into the produced binary as an RPATH,
so executables run without `LD_LIBRARY_PATH`.

## Usage example

```crystal
require "itb"

# Single Message: sender initializes a session, receiver opens it
# from the exported blob.
sender = ITB::Pipeline.new("singlemsg-triple-mac-v1")
receiver = ITB::Pipeline.new("singlemsg-triple-mac-v1", sender.blob)

wire = sender.encrypt_message("attack at dawn".to_slice)
plain = receiver.decrypt_message(wire) # => "attack at dawn".to_slice

# Streaming AEAD: incremental sessions over a streaming profile.
s = ITB::Pipeline.new("streaming-aead-triple-mac-v1")
r = ITB::Pipeline.new("streaming-aead-triple-mac-v1", s.blob)

enc = s.encrypt_stream
enc.write(chunk1)
enc.write(chunk2)
wire = enc.drain_all # ends the input and drains the remaining wire
enc.free

dec = r.decrypt_stream
dec.write(wire)
dec.end_stream
loop do
  chunk, finished = dec.read
  process(chunk)
  break if finished
end
dec.free

# Opts pass-through (validated by Go; unknown keys are rejected).
opts = ITB::Opts.new
  .with_nonce_bits(512)
  .with_inner_hash("areion512")
pipe = ITB::Pipeline.new("singlemsg-triple-nomac-v1", opts: opts)

# Master rotation refreshes the exported blob.
pipe.rekey(perm_master, wrap_master)

# Go runtime knobs (a negative value queries without changing).
ITB.set_memory_limit(512_i64 << 20)
ITB.set_gc_percent(20)

# Registry roster.
ITB.version  # => libitb version string
ITB.hashes   # => [ITB::HashInfo(name, width), ...] in canonical order
ITB.profiles # => shipped profile identifiers
```

`ITB::Opts` overrides the profile default per call (chunk size,
outer cipher, parallax on/off, wrapper on/off, MAC name, palette);
every setter returns the same builder for fluent chaining:

```crystal
opts = ITB::Opts.new.with_chunk_size(65536).with_wrapper(false)
sender = ITB::Pipeline.new("singlemsg-triple-mac-v1", opts: opts)
receiver = ITB::Pipeline.new("singlemsg-triple-mac-v1", sender.blob, opts: opts)
```

`Pipeline#rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design); the receiver picks up the new masters through a fresh
`sender.blob` handshake:

```crystal
sender.rekey(Bytes.new(32, 0x11_u8), Bytes.new(32, 0x22_u8))
receiver = ITB::Pipeline.new("singlemsg-triple-mac-v1", sender.blob)
```

Every fallible call raises `ITB::Error`, which carries `status`
(the `ITB::Status` enum), `status_code` (raw integer), and
`last_error` (the `ITB_LastError` diagnostic). Garbage collection
releases Go-side handles; call `Pipeline#free` / session `#free` for
deterministic release. A stream session holds a reference to its
parent Pipeline, so the parent cannot be collected while the session
is reachable.

## Testing

```bash
./bindings/crystal/run_tests.sh
```

Runs `crystal spec`: version and roster checks (canonical hash order,
shipped profiles), Single Message and incremental-stream round trips
(including pathological 17-byte feed / 23-byte drain batches), a
large-plaintext round trip past 1 MiB, error mapping (unknown
profile, unknown opts key, tampered wire, closed pipeline), rekey,
custom-profile registration, opts encoding, and the stream-session
parent-pin.

## Benchmarking

```bash
./bindings/crystal/run_bench.sh
```

Compiles `bench/bench.cr` with `--release` and measures Single
Message encrypt and incremental Streaming encrypt throughput at
1 MiB / 16 MiB / 64 MiB under the canonical fleet configuration
(Areion-SoEM-512, 1024-bit key, 512-bit nonce, parallax and wrapper
off, No MAC profiles, 5 s wall-clock per case; see
[BENCH.md](../BENCH.md)). Shape overrides via `ITB_INNER_HASH`,
`ITB_KEY_BITS`, `ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`,
`ITB_WITH_WRAPPER`, `ITB_PROFILE`, `ITB_BENCH_MIN_SEC`.

## eitb CLI

```bash
./bindings/crystal/eitb/eitb version
./bindings/crystal/eitb/eitb hashes
./bindings/crystal/eitb/eitb profiles
./bindings/crystal/eitb/eitb encrypt <profile> <in-file> <out-file>
./bindings/crystal/eitb/eitb decrypt <profile> <blob-hex> <in-file> <out-file>
```

`encrypt` prints the session blob to stderr as hex; feed that hex
back to `decrypt` on the receiving side.

## Limitations

- **Compile-time linking.** Library resolution happens when the
  Crystal program is compiled, not at process start — moving
  `libitb.so` after compilation requires either the baked RPATH to
  stay valid or `LD_LIBRARY_PATH` at run time. `ITB_LIBITB_PATH` set
  at compile time overrides the search.
- **Blocking FFI calls.** Every binding call blocks the calling
  thread until libitb returns; the calls do not integrate with
  Crystal's fiber scheduler. Long encrypt / decrypt operations should
  not share a thread with latency-sensitive fibers.
- **Streaming-decrypt caveat.** Chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication. Consumers requiring
  whole-message authentication before any plaintext release should
  use Single Message profiles (`singlemsg-triple-mac-v1`).
- **Triple surface only.** The binding exposes the Triple Pipeline
  facade; the Low-Level configuration surface stays Go-native and is
  not exported here.
- **Profile roster is pinned.** The C ABI exposes no profile
  enumeration; `ITB.profiles` returns the shipped identifiers pinned
  in the binding and does not include profiles registered at runtime.
