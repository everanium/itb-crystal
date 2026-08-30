# Thin Crystal proxy over the libitb shared library's Triple Pipeline
# surface.
#
# The shard wraps the `ITB_Triple_*` C ABI exported by `cmd/cshared`
# (libitb.so / .dylib) through Crystal's native `lib` bindings. Every
# hash-name / MAC-name / cipher-name / profile-name is an opaque
# string passed through to Go for validation; the binding carries no
# ITB construction logic of its own.
#
# ```
# require "itb"
#
# sender = ITB::Pipeline.new("singlemsg-triple-mac-v1")
# receiver = ITB::Pipeline.new("singlemsg-triple-mac-v1", sender.blob)
# wire = sender.encrypt_message("hello".to_slice)
# receiver.decrypt_message(wire) # => "hello".to_slice
# ```

require "./itb/ffi_bridge"
require "./itb/errors"
require "./itb/opts"
require "./itb/pipeline"
require "./itb/stream"

module ITB
  # Binding version (matches shard.yml).
  VERSION = "0.3.0"

  # Shipped profile identifiers, mirrored from the Go triple package
  # registry in declaration order. The C ABI exposes no profile
  # enumeration, so the roster is pinned here; profiles registered at
  # runtime via `ITB.register_profile` are not included.
  PROFILES = [
    "streaming-aead-triple-mac-v1",
    "streaming-noaead-triple-v1",
    "singlemsg-triple-mac-v1",
    "singlemsg-triple-nomac-v1",
    "blob-triple-mac-v1",
    "streaming-aead-triple-mac-mixed-v1",
    "streaming-noaead-triple-mixed-v1",
    "singlemsg-triple-mac-mixed-v1",
    "singlemsg-triple-nomac-mixed-v1",
  ]

  # One shipped hash-registry row (`ITB_HashName` / `ITB_HashWidth`).
  record HashInfo, name : String, width : Int32

  # Returns the libitb library version string.
  def self.version : String
    read_cstr { |out_p, cap, len_p| LibItb.version(out_p, cap, len_p) }
  end

  # Returns the shipped hash primitive registry in canonical order.
  def self.hashes : Array(HashInfo)
    n = LibItb.hash_count
    Array(HashInfo).new(n) do |i|
      buf = Bytes.new(128)
      len = LibC::SizeT.zero
      rc = LibItb.hash_name(i, buf.to_unsafe.as(LibC::Char*), LibC::SizeT.new(buf.size), pointerof(len))
      raise Error.from_rc(rc) unless rc == Status::Ok.value
      name = String.new(buf[0, len > 0 ? len - 1 : LibC::SizeT.zero])
      HashInfo.new(name, LibItb.hash_width(i))
    end
  end

  # Returns the shipped profile identifiers (a copy of `PROFILES`).
  def self.profiles : Array(String)
    PROFILES.dup
  end

  # Sets the Go runtime's soft heap limit in bytes and returns the
  # previous limit. A negative value queries without changing.
  def self.set_memory_limit(bytes : Int64) : Int64
    LibItb.set_memory_limit(bytes)
  end

  # :ditto:
  def self.set_memory_limit(bytes : Int) : Int64
    set_memory_limit(bytes.to_i64)
  end

  # Sets the Go GC trigger percentage and returns the previous value.
  # A negative value queries without changing.
  def self.set_gc_percent(pct : Int32) : Int32
    LibItb.set_gc_percent(pct)
  end

  # Registers a user-defined Triple profile under `name` so subsequent
  # `Pipeline.new` calls resolve it. The opts follow the
  # register-profile grammar validated by Go (`mode`, `width`,
  # `innerHash` / `innerHashes`, `keyBits`, `macName`, `outerCipher`,
  # `parallaxPalette`, `parallaxSegmentSize`, `chunkSize`,
  # `parallaxOn`, `wrapperOn`) — build them with `Opts#with_raw` plus
  # the typed setters where key names coincide. A duplicate name
  # fails with `Status::ProfileExists`.
  def self.register_profile(name : String, opts : Opts) : Nil
    check(LibItb.triple_register_profile(name, opts.build))
  end

  # Two-phase read over the `(out, cap, *out_len)` C-string contract:
  # probe with NULL / 0 for the required capacity, then read and
  # NUL-strip.
  private def self.read_cstr(& : (LibC::Char*, LibC::SizeT, LibC::SizeT*) -> Int32) : String
    need = LibC::SizeT.zero
    rc = yield Pointer(LibC::Char).null, LibC::SizeT.zero, pointerof(need)
    unless rc == Status::Ok.value || rc == Status::BufferTooSmall.value
      raise Error.from_rc(rc)
    end
    return "" if need <= 1
    buf = Bytes.new(need)
    rc = yield buf.to_unsafe.as(LibC::Char*), LibC::SizeT.new(buf.size), pointerof(need)
    check(rc)
    String.new(buf[0, need - 1])
  end
end
