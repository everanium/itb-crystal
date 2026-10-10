# Thin Crystal proxy over the libitb3 shared library's Triple Pipeline
# surface.
#
# The shard wraps the `ITB_Triple_*` C ABI exported by `cmd/cshared`
# (libitb3.so / .dylib) through Crystal's native `lib` bindings. Every
# hash-name / MAC-name / cipher-name / profile-name is an opaque
# string passed through to Go for validation; the binding carries no
# ITB construction logic of its own.
#
# ```
# require "libitb3"
#
# sender = ITB::Pipeline.new("singlemsg-triple-mac-v1")
# receiver = ITB::Pipeline.load(sender.save)
# wire = sender.encrypt_message("hello".to_slice)
# receiver.decrypt_message(wire) # => "hello".to_slice
# ```

require "./itb/ffi_bridge"
require "./itb/errors"
require "./itb/opts"
require "./itb/profile"
require "./itb/pipeline"
require "./itb/stream"

module ITB
  # Binding version (matches shard.yml).
  VERSION = "0.5.5"

  # Floor capacity for profile-JSON output buffers (inspect / lookup
  # / profiles).
  JSON_CAP = 4096

  # Returns the libitb3 library version string.
  def self.version : String
    read_cstr { |out_p, cap, len_p| ITB.blocking(->{ LibItb3.version(out_p, cap, len_p) }) }
  end

  # Returns the fill cipher the auto DRBG tier selected on this host
  # (`"aes-256-ctr"` or `"chacha20"`): the tier a Pipeline uses when its
  # drbg option is empty, resolved per host and recorded in no blob.
  def self.drbg_auto_tier : String
    read_cstr { |out_p, cap, len_p| ITB.blocking(->{ LibItb3.drbg_auto_tier(out_p, cap, len_p) }) }
  end

  # Returns the sorted names of every registered profile — the shipped
  # catalogue plus prior `ITB.register` calls (`ITB_Triple_Profiles`).
  def self.profiles : Array(String)
    json = retry_once(JSON_CAP) do |buf, len_p|
      ITB.blocking(->{ LibItb3.triple_profiles(buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p) })
    end
    Profile.strings_from_json(String.new(json))
  end

  # Decodes the blob's embedded profile record without opening a
  # Pipeline (`ITB_Triple_Inspect`). No registry read, no primitive
  # probe.
  def self.inspect(blob : Bytes) : Profile
    json = retry_once(JSON_CAP) do |buf, len_p|
      ITB.blocking(->{ LibItb3.triple_inspect(blob.to_unsafe.as(Void*), LibC::SizeT.new(blob.size),
        buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p) })
    end
    Profile.from_json(String.new(json))
  end

  # Looks up a registered profile (shipped or `ITB.register`ed) by
  # name (`ITB_Triple_Lookup`); an unknown name raises with
  # `Status::UnknownProfile`.
  def self.lookup(name : String) : Profile
    json = retry_once(JSON_CAP) do |buf, len_p|
      ITB.blocking(->{ LibItb3.triple_lookup(name, buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p) })
    end
    Profile.from_json(String.new(json))
  end

  # Sets the Go runtime's soft heap limit in bytes and returns the
  # previous limit. A negative value queries without changing.
  def self.set_memory_limit(bytes : Int64) : Int64
    ITB.blocking(->{ LibItb3.set_memory_limit(bytes) })
  end

  # :ditto:
  def self.set_memory_limit(bytes : Int) : Int64
    set_memory_limit(bytes.to_i64)
  end

  # Sets the Go GC trigger percentage and returns the previous value.
  # A negative value queries without changing.
  def self.set_gc_percent(pct : Int32) : Int32
    ITB.blocking(->{ LibItb3.set_gc_percent(pct) })
  end

  # Sets the Go runtime's GOMAXPROCS and returns the previous value.
  # Zero or a negative value queries without changing.
  def self.set_gomaxprocs(n : Int32) : Int32
    ITB.blocking(->{ LibItb3.set_gomaxprocs(n) })
  end

  # Writes the Go runtime's heap profile (pprof format) to *path*
  # after one forced garbage collection. An empty path falls back to
  # the `ITB_MEMPROFILE` environment variable; a path that is still
  # empty, or a file-system failure, raises `ITB::Error` carrying
  # `Status::BadInput`.
  def self.write_heap_profile(path : String) : Nil
    check(ITB.blocking(->{ LibItb3.write_heap_profile(path) }))
  end

  # Number of `Int64` slots `pool_stats` fills. Size the destination
  # from this call, never from a constant.
  def self.pool_stats_len : Int32
    n = ITB.blocking(->{ LibItb3.pool_stats_len })
    n > 0 ? n : 0
  end

  # Copies the library's pool hit / miss counters into *dst* and
  # returns the slot count written. Every counter is a monotonically
  # increasing total since library load; difference two snapshots.
  # Slot layout, with `T` the tier count in slot 0: tier `i` holds
  # starter width, checkouts, constructor misses, regrow replacements
  # and bytes allocated at slots `1 + 5*i .. 1 + 5*i + 4`; the scratch
  # byte pool's get / new / regrow / regrow-bytes follow at `1 + 5*T`,
  # and the parallax chunk pool's at `1 + 5*T + 4`. A *dst* shorter
  # than `pool_stats_len` raises with `Status::BufferTooSmall`.
  def self.pool_stats(dst : Slice(Int64)) : Int32
    written = LibC::SizeT.zero
    check(ITB.blocking(->{ LibItb3.pool_stats(dst.to_unsafe, LibC::SizeT.new(dst.size), pointerof(written)) }))
    written.to_i32
  end

  # Returns the shipped hash-primitive registry in canonical order
  # (`ITB_Triple_HashNames`). The registry is the authority on which
  # names `Pipeline.new` accepts for the `innerHash` opts key.
  def self.hash_names : Array(String)
    json = retry_once(JSON_CAP) do |buf, len_p|
      ITB.blocking(->{ LibItb3.triple_hash_names(buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p) })
    end
    Profile.strings_from_json(String.new(json))
  end

  # Registers *profile* under *name* so subsequent `Pipeline.new` /
  # `ITB.lookup` calls resolve it (`ITB_Triple_Register`). Every
  # field rule is validated by Go; a duplicate name fails with
  # `Status::ProfileExists`.
  def self.register(name : String, profile : Profile) : Nil
    check(ITB.blocking(->{ LibItb3.triple_register(name, profile.to_json) }))
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
