# Plaintext content: the payload modes, the seeded per-worker
# generator, and the buffer fill from the operating-system CSPRNG.

# Crystal-specific. The standard library's secure random reaches the
# kernel through its own path; the C entry is declared here instead so
# the fill goes through the same libc wrapper every other
# implementation calls.
lib LibLoopRandom
  fun getrandom(buf : Void*, buflen : LibC::SizeT, flags : LibC::UInt) : LibC::SSizeT
end

module Loop
  # Plaintext content policies the --payload-mode flag selects.
  #
  #   - Fixed: one CSPRNG-generated buffer per worker, held unchanged
  #     for the whole run (the default).
  #   - Rotating: the buffer is regenerated before every iteration, so
  #     no two encrypt calls see the same plaintext.
  #   - PatternZero / PatternFF: degenerate constant fills (all 0x00 /
  #     all 0xFF) probing minimum-entropy plaintext handling.
  #   - PatternAscii: a repeating 'A'..'Z' ramp probing low-entropy
  #     structured text.
  enum PayloadMode
    Fixed
    Rotating
    PatternZero
    PatternFF
    PatternAscii
  end

  PAYLOAD_NAMES = ["fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii"]

  def self.payload_mode_name(mode : PayloadMode) : String
    PAYLOAD_NAMES[mode.value]
  end

  def self.parse_payload_mode(s : String) : PayloadMode?
    idx = PAYLOAD_NAMES.index(s)
    idx.nil? ? nil : PayloadMode.new(idx)
  end

  # Seeded plaintext. The seed makes plaintext content reproducible so
  # a failing iteration can be replayed with the same bytes; it governs
  # nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
  # so a seeded run is a reproduction aid and never a security test.
  # Each worker's stream is domain-separated by its id so seeded
  # workers still hold pairwise-distinct buffers under the fixed and
  # rotating modes. The generator is splitmix64: a few lines in any
  # language, which is why it is the one every binding uses.
  def self.seed_worker(seed : UInt64, worker_id : Int32) : UInt64
    seed &+ worker_id.to_u64 &+ 1_u64
  end

  # One splitmix64 step; *state* is advanced in place by the caller.
  def self.splitmix64(state : UInt64) : {UInt64, UInt64}
    s = state &+ 0x9E3779B97F4A7C15_u64
    z = s
    z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9_u64
    z = (z ^ (z >> 27)) &* 0x94D049BB133111EB_u64
    {s, z ^ (z >> 31)}
  end

  # Fills *buf* from the operating-system CSPRNG. The syscall returns
  # at most ~33 MiB per call and may return short on a signal, so the
  # fill loops until every byte is in place.
  def self.fill_random(buf : Bytes) : Bool
    off = 0
    while off < buf.size
      r = LibLoopRandom.getrandom((buf.to_unsafe + off).as(Void*),
        LibC::SizeT.new(buf.size - off), 0_u32)
      return false if r <= 0
      off += r.to_i
    end
    true
  end

  # Writes one plaintext buffer according to the payload mode. The
  # fixed and rotating modes draw from the seeded generator when the
  # run is seeded and from the OS CSPRNG otherwise; the pattern modes
  # are deterministic regardless of the seed. Returns false when the
  # CSPRNG fails; *rng* is the generator state, advanced and returned.
  def self.fill_payload(mode : PayloadMode, seeded : Bool, rng : UInt64,
                        buf : Bytes) : {Bool, UInt64}
    case mode
    when PayloadMode::Fixed, PayloadMode::Rotating
      return {fill_random(buf), rng} unless seeded
      state = rng
      i = 0
      while i < buf.size
        state, v = splitmix64(state)
        take = Math.min(buf.size - i, 8)
        take.times { |k| buf[i + k] = ((v >> (8 * k)) & 0xFF).to_u8 }
        i += 8
      end
      {true, state}
    when PayloadMode::PatternZero
      buf.fill(0_u8)
      {true, rng}
    when PayloadMode::PatternFF
      buf.fill(0xFF_u8)
      {true, rng}
    else
      buf.size.times { |i| buf[i] = ('A'.ord + (i % 26)).to_u8 }
      {true, rng}
    end
  end
end
