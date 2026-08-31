# URL-query builder for the opts pass-through string.
#
# The builder performs no validation — every key and value is
# rendered into a percent-encoded query string and passed through to
# Go verbatim; libitb rejects unknown keys or bad values with a
# diagnostic surfaced via `ITB::Error`. Primitive / MAC / cipher /
# palette names are opaque strings.

module ITB
  # Fluent builder producing the URL-query-encoded opts string
  # consumed by `Pipeline.new` and `ITB.register_profile`.
  class Opts
    def initialize
      @pairs = [] of {String, String}
    end

    # Hex-encodes the parallax master override (`pm`).
    def with_perm_master(master : Bytes) : self
      with_raw("pm", master.hexstring)
    end

    # Hex-encodes the wrapper master override (`wm`).
    def with_wrap_master(master : Bytes) : self
      with_raw("wm", master.hexstring)
    end

    def with_parallax(on : Bool) : self
      with_raw("withParallax", on.to_s)
    end

    def with_wrapper(on : Bool) : self
      with_raw("withWrapper", on.to_s)
    end

    def with_max_workers(n : Int) : self
      with_raw("maxWorkers", n.to_s)
    end

    def with_nonce_bits(n : Int) : self
      with_raw("nonceBits", n.to_s)
    end

    def with_barrier_fill(n : Int) : self
      with_raw("barrierFill", n.to_s)
    end

    def with_chunk_size(n : Int) : self
      with_raw("chunkSize", n.to_s)
    end

    def with_key_bits(n : Int) : self
      with_raw("keyBits", n.to_s)
    end

    def with_parallax_segment_size(n : Int) : self
      with_raw("parallaxSegmentSize", n.to_s)
    end

    def with_mac_name(name : String) : self
      with_raw("macName", name)
    end

    def with_inner_hash(name : String) : self
      with_raw("innerHash", name)
    end

    # Per-call constellation override mirroring the Go-side
    # `Opts.MixedHashes [8]string` field: the 8 slot names are
    # comma-joined into the `innerHashes` pass-through key in the
    # slot order `[noise, lock, data1, data2, data3, start1, start2,
    # start3]`. Fail-fast validation surfaces at Init on the Go side;
    # a typo'd slot or width mismatch surfaces with an error naming
    # the offending slot. When both this and `with_inner_hash` are
    # set, the mixed override wins on the Go side.
    def with_inner_hashes(names : Enumerable(String)) : self
      with_raw("innerHashes", names.join(","))
    end

    def with_outer_cipher(name : String) : self
      with_raw("outerCipher", name)
    end

    # Comma-joins the palette names (`parallaxPalette`).
    def with_parallax_palette(names : Enumerable(String)) : self
      with_raw("parallaxPalette", names.join(","))
    end

    # Escape hatch appending a raw `key=value` pair. Covers every key
    # the Go side accepts, including the register-profile grammar
    # (`mode`, `width`, `innerHashes`, `parallaxOn`, `wrapperOn`, …).
    def with_raw(key : String, value : String) : self
      @pairs << {key, value}
      self
    end

    # Renders the accumulated pairs as a query string.
    def build : String
      @pairs.join("&") { |(k, v)| "#{Opts.encode(k)}=#{Opts.encode(v)}" }
    end

    # :nodoc:
    # Minimal percent-encoding: the accepted values are ASCII names,
    # decimal integers, `true` / `false`, hex, and comma-separated
    # lists, so everything outside the URL-safe subset (plus `,`) is
    # escaped byte-wise.
    def self.encode(s : String) : String
      String.build(s.bytesize) do |io|
        s.each_byte do |b|
          case b
          when 'A'.ord..'Z'.ord, 'a'.ord..'z'.ord, '0'.ord..'9'.ord,
               '-'.ord, '.'.ord, '_'.ord, '~'.ord, ','.ord
            io << b.unsafe_chr
          else
            io << '%'
            io << b.to_s(16, upcase: true).rjust(2, '0')
          end
        end
      end
    end
  end
end
