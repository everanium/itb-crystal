# bench.cr — micro-benchmarks for the ITB Crystal binding.
#
# Single Message encrypt and incremental Streaming encrypt throughput
# at 1 MiB / 16 MiB / 64 MiB. Wall-clock via the POSIX monotonic clock
# (stable across Crystal versions; the std-lib monotonic entry point
# was renamed between releases); output is a fixed-width table:
#
#     bench             size     mb_per_sec
#     message           1 MiB    <n>
#     ...
#
# Configuration is driven by environment variables so a side-by-side
# comparison with the root Go bench harness is straightforward:
#
#     ITB_NONCE_BITS      512         shipped secure default
#     ITB_KEY_BITS        1024        matches root Go BENCH3.md
#     ITB_WITH_PARALLAX   false       root Go bench runs without parallax
#     ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
#     ITB_INNER_HASH      (profile)   opaque hash name
#     ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
#     ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
#     ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds)

require "../src/itb"

SIZES           = [1 << 20, 16 << 20, 64 << 20]
BENCH_MIN_ITERS = 3
PUMP_SLICE      = 1 << 20

# Monotonic wall-clock seconds (POSIX CLOCK_MONOTONIC).
def mono_seconds : Float64
  LibC.clock_gettime(LibC::CLOCK_MONOTONIC, out ts)
  ts.tv_sec.to_f64 + ts.tv_nsec.to_f64 / 1e9
end

def env(name : String, fallback : String) : String
  v = ENV[name]?
  v.nil? || v.empty? ? fallback : v
end

# Reads the per-shape profile env var, falling back to ITB_PROFILE,
# then to the shape's own default.
def profile_env(shape_env : String, fallback : String) : String
  env(shape_env, env("ITB_PROFILE", fallback))
end

def bench_min_seconds : Float64
  v = env("ITB_BENCH_MIN_SEC", "5").to_f?
  v.nil? || v <= 0 ? 5.0 : v
end

# Reads the bench-shape env vars and builds the opts. Defaults match
# the root Go BENCH3.md pin so numbers are directly comparable.
def build_opts : ITB::Opts
  opts = ITB::Opts.new
    .with_nonce_bits(env("ITB_NONCE_BITS", "512").to_i)
    .with_key_bits(env("ITB_KEY_BITS", "1024").to_i)
    .with_parallax(env("ITB_WITH_PARALLAX", "false") == "true")
    .with_wrapper(env("ITB_WITH_WRAPPER", "false") == "true")
  inner = env("ITB_INNER_HASH", "")
  opts = opts.with_inner_hash(inner) unless inner.empty?
  mac = env("ITB_MAC_NAME", "")
  opts = opts.with_mac_name(mac) unless mac.empty?
  opts
end

def size_label(size : Int32) : String
  size >= (1 << 20) ? "#{size >> 20} MiB" : "#{size >> 10} KiB"
end

# Runs the block until the wall-clock budget is spent (with an
# iteration floor + one untimed warm-up), then prints one table row.
def bench_case(name : String, size : Int32, &) : Nil
  yield # warm-up
  budget = bench_min_seconds
  start = mono_seconds
  elapsed = 0.0
  iters = 0
  while elapsed < budget || iters < BENCH_MIN_ITERS
    yield
    iters += 1
    elapsed = mono_seconds - start
  end
  mb = size.to_f64 * iters / (1024.0 * 1024.0)
  printf("%-17s %-8s %.1f\n", name, size_label(size), mb / elapsed)
end

# One incremental encrypt-session pass: feed 1 MiB slices, drain
# available wire as it appears, then end + final drain.
def stream_pass(pipe : ITB::Pipeline, plain : Bytes, outbuf : Bytes) : Nil
  sess = pipe.encrypt_stream
  off = 0
  while off < plain.size
    n = Math.min(PUMP_SLICE, plain.size - off)
    sess.write(plain[off, n])
    off += n
    loop do
      m, _ = sess.read_into(outbuf)
      break if m == 0
    end
  end
  sess.end_stream
  loop do
    _, finished = sess.read_into(outbuf)
    break if finished
  end
  sess.free
end

# Decrypt counterpart: feed slices from wire, drain available plain.
def stream_pass_dec(pipe : ITB::Pipeline, wire : Bytes, outbuf : Bytes) : Nil
  sess = pipe.decrypt_stream
  off = 0
  while off < wire.size
    n = Math.min(PUMP_SLICE, wire.size - off)
    sess.write(wire[off, n])
    off += n
    loop do
      m, _ = sess.read_into(outbuf)
      break if m == 0
    end
  end
  sess.end_stream
  loop do
    _, finished = sess.read_into(outbuf)
    break if finished
  end
  sess.free
end

# Pre-encrypt one wire outside the decrypt timing loop.
def stream_encrypt_all(pipe : ITB::Pipeline, plain : Bytes, outbuf : Bytes) : Bytes
  parts = [] of Bytes
  sess = pipe.encrypt_stream
  off = 0
  while off < plain.size
    n = Math.min(PUMP_SLICE, plain.size - off)
    sess.write(plain[off, n])
    off += n
    loop do
      m, _ = sess.read_into(outbuf)
      break if m == 0
      parts << outbuf[0, m].clone
    end
  end
  sess.end_stream
  loop do
    m, finished = sess.read_into(outbuf)
    parts << outbuf[0, m].clone if m > 0
    break if finished
  end
  sess.free
  total = parts.sum(&.size)
  wire = Bytes.new(total)
  off = 0
  parts.each do |p|
    p.copy_to(wire[off, p.size])
    off += p.size
  end
  wire
end

# Bench-scale allocation churn leaks Go scratch heap unboundedly
# without a soft memory cap + aggressive GC; the return values report
# the previous settings, not an error.
ITB.set_memory_limit(512_i64 << 20)
ITB.set_gc_percent(20)

opts = build_opts
printf("%-17s %-8s mb_per_sec\n", "bench", "size")

begin
  pipe = ITB::Pipeline.new(profile_env("ITB_MSG_PROFILE", "singlemsg-triple-nomac-v1"), opts: opts)
  SIZES.each do |size|
    # CSPRNG-fill so plaintext content matches the root Go bench
    # (crypto/rand). Not in the timing loop.
    plain = Random::Secure.random_bytes(size)
    bench_case("message", size) { pipe.encrypt_message(plain) }
    # Pre-encrypt one wire outside the decrypt timing loop.
    dec_wire = pipe.encrypt_message(plain)
    bench_case("message-dec", size) { pipe.decrypt_message(dec_wire) }
    GC.collect
  end
  pipe.free
end

begin
  pipe = ITB::Pipeline.new(profile_env("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), opts: opts)
  outbuf = Bytes.new(PUMP_SLICE)
  SIZES.each do |size|
    plain = Random::Secure.random_bytes(size)
    bench_case("stream", size) { stream_pass(pipe, plain, outbuf) }
    dec_wire = stream_encrypt_all(pipe, plain, outbuf)
    bench_case("stream-dec", size) { stream_pass_dec(pipe, dec_wire, outbuf) }
    GC.collect
  end
  pipe.free
end

# Whole-buffer stream: one FFI round trip through
# encrypt_stream_one_shot / decrypt_stream_one_shot per iteration.
begin
  pipe = ITB::Pipeline.new(profile_env("ITB_STREAM_PROFILE", "streaming-noaead-triple-v1"), opts: opts)
  SIZES.each do |size|
    plain = Random::Secure.random_bytes(size)
    bench_case("stream_one_shot", size) { pipe.encrypt_stream_one_shot(plain) }
    dec_wire = pipe.encrypt_stream_one_shot(plain)
    bench_case("stream_one_shot-dec", size) { pipe.decrypt_stream_one_shot(dec_wire) }
    GC.collect
  end
  pipe.free
end
