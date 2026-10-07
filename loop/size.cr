# Size and duration parsing, the monotonic clock, and the human
# renderings of sizes, rates and durations. Every rendering here is
# part of the output contract shared with the Go harness and the other
# bindings' loop utilities, so the formats are fixed to the character,
# not to taste.

# Crystal-specific. The fractional renderings go through C's snprintf
# rather than the standard library's formatter, so the digits a summary
# carries are the ones every other implementation prints without
# resting on the two agreeing on every rounding tie.
lib LibLoopFmt
  fun snprintf(str : LibC::Char*, size : LibC::SizeT, format : LibC::Char*, ...) : LibC::Int
end

module Loop
  # Process start instant; every clock reading is a span from here, so
  # the sequence is monotonic and free of wall-clock adjustments.
  START_INSTANT = Time.instant

  # Renders *v* under a C floating-point conversion specifier.
  def self.fmt_f(spec : String, v : Float64) : String
    buf = uninitialized UInt8[64]
    n = LibLoopFmt.snprintf(buf.to_unsafe.as(LibC::Char*),
      LibC::SizeT.new(buf.size), spec, v)
    n > 0 ? String.new(buf.to_unsafe, n) : ""
  end

  # Parses a human byte-size string ("16MB", "1MiB", "512K",
  # "1073741824") into a byte count. Every suffix is a binary multiple:
  # K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
  # bytes; matching is case-insensitive and surrounding whitespace is
  # trimmed. Returns nil on a malformed or negative value.
  SIZE_SUFFIXES = [
    {"KIB", 1_i64 << 10}, {"KB", 1_i64 << 10}, {"K", 1_i64 << 10},
    {"MIB", 1_i64 << 20}, {"MB", 1_i64 << 20}, {"M", 1_i64 << 20},
    {"GIB", 1_i64 << 30}, {"GB", 1_i64 << 30}, {"G", 1_i64 << 30},
    {"B", 1_i64},
  ]

  def self.parse_size(s : String) : Int64?
    upper = s.strip.upcase
    return nil if upper.empty? || upper.size >= 64
    mult = 1_i64
    digits = upper.size
    SIZE_SUFFIXES.each do |(suffix, m)|
      if upper.size >= suffix.size && upper.ends_with?(suffix)
        mult = m
        digits = upper.size - suffix.size
        break
      end
    end
    while digits > 0 && upper[digits - 1].whitespace?
      digits -= 1
    end
    return nil if digits == 0
    head = upper[0, digits]
    return nil unless head.each_char.all? { |c| c.ascii_number? }
    n = head.to_i64?
    return nil if n.nil? || n < 0
    return nil if mult > 1 && n > Int64::MAX // mult
    n * mult
  end

  # Parses the Go duration grammar — a sequence of decimal numbers each
  # followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
  # "1h30m", "1.5s" — into nanoseconds. Returns nil on a malformed
  # string.
  DURATION_UNITS = [
    {"ns", 1.0}, {"us", 1e3}, {"ms", 1e6},
    {"s", 1e9}, {"m", 60e9}, {"h", 3600e9},
  ]

  def self.parse_duration(s : String) : Int64?
    return nil if s.empty?
    total = 0.0
    i = 0
    while i < s.size
      return nil unless s[i].ascii_number? || s[i] == '.'
      j = i
      while j < s.size && (s[j].ascii_number? || s[j] == '.')
        j += 1
      end
      v = s[i, j - i].to_f64?
      return nil if v.nil? || v < 0.0
      i = j
      mult = 0.0
      DURATION_UNITS.each do |(unit, m)|
        next unless s.size - i >= unit.size && s[i, unit.size] == unit
        next unless s.size - i == unit.size || !s[i + unit.size].ascii_letter?
        mult = m
        i += unit.size
        break
      end
      return nil if mult == 0.0
      total += v * mult
    end
    return nil if total > 9.2e18
    total.to_i64
  end

  # Monotonic wall clock in nanoseconds.
  def self.now_ns : Int64
    (Time.instant - START_INSTANT).total_nanoseconds.to_i64
  end

  # Renders a byte count with a binary-unit suffix: "1.0GiB",
  # "16.0MiB", "4.0KiB", "512B".
  def self.human_bytes(n : Int64) : String
    if n >= (1_i64 << 30)
      fmt_f("%.1f", n.to_f / (1_i64 << 30).to_f) + "GiB"
    elsif n >= (1_i64 << 20)
      fmt_f("%.1f", n.to_f / (1_i64 << 20).to_f) + "MiB"
    elsif n >= (1_i64 << 10)
      fmt_f("%.1f", n.to_f / (1_i64 << 10).to_f) + "KiB"
    else
      "#{n}B"
    end
  end

  # Renders a possibly-negative byte delta with an explicit sign.
  def self.human_bytes_signed(n : Int64) : String
    n < 0 ? "-" + human_bytes(-n) : "+" + human_bytes(n)
  end

  # Binary MiB per second over a nanosecond window; 0 when the window
  # is unmeasured.
  def self.mb_per_sec(bytes : Int64, ns : Int64) : Float64
    return 0.0 if ns <= 0
    bytes.to_f / (1 << 20).to_f / (ns.to_f / 1e9)
  end

  # Renders a throughput as "123.4MB/s" (binary MiB per second) or
  # "n/a" for an unmeasured window.
  def self.human_rate(bytes : Int64, ns : Int64) : String
    return "n/a" if ns <= 0
    fmt_f("%.1f", mb_per_sec(bytes, ns)) + "MB/s"
  end

  # The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
  # with trailing zeros removed; the empty string for zero.
  private def self.fraction(frac_ns : Int64) : String
    return "" if frac_ns == 0
    digits = frac_ns.to_s.rjust(9, '0')
    digits = digits.rstrip('0')
    "." + digits
  end

  # Renders a duration the way Go's time.Duration prints: below one
  # second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
  # where the hour part appears when non-zero, the minute part when the
  # hour part appears or the minutes are non-zero, and the seconds
  # carry their fraction with trailing zeros removed ("5s", "5.003s",
  # "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
  def self.human_duration(ns_in : Int64) : String
    ns = ns_in < 0 ? -ns_in : ns_in
    return "0s" if ns == 0
    if ns < 1_000_000_000_i64
      return "#{ns // 1_000_000_i64}" +
        fraction((ns % 1_000_000_i64) * 1000_i64) + "ms"
    end
    hours = ns // 3_600_000_000_000_i64
    rem = ns % 3_600_000_000_000_i64
    minutes = rem // 60_000_000_000_i64
    rem %= 60_000_000_000_i64
    seconds = rem // 1_000_000_000_i64
    frac = rem % 1_000_000_000_i64
    out = String.build do |io|
      io << hours << 'h' if hours > 0
      io << minutes << 'm' if hours > 0 || minutes > 0
      io << seconds << fraction(frac) << 's'
    end
    out
  end
end
