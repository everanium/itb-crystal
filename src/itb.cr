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
  VERSION = "0.4.1"

  # Floor capacity for profile-JSON output buffers (inspect / lookup
  # / profiles).
  JSON_CAP = 4096

  # Returns the libitb library version string.
  def self.version : String
    read_cstr { |out_p, cap, len_p| LibItb.version(out_p, cap, len_p) }
  end

  # Returns the sorted names of every registered profile — the shipped
  # catalogue plus prior `ITB.register` calls (`ITB_Triple_Profiles`).
  def self.profiles : Array(String)
    json = retry_once(JSON_CAP) do |buf, len_p|
      LibItb.triple_profiles(buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
    end
    Profile.strings_from_json(String.new(json))
  end

  # Decodes the blob's embedded profile record without opening a
  # Pipeline (`ITB_Triple_Inspect`). No registry read, no primitive
  # probe.
  def self.inspect(blob : Bytes) : Profile
    json = retry_once(JSON_CAP) do |buf, len_p|
      LibItb.triple_inspect(blob.to_unsafe.as(Void*), LibC::SizeT.new(blob.size),
        buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
    end
    Profile.from_json(String.new(json))
  end

  # Looks up a registered profile (shipped or `ITB.register`ed) by
  # name (`ITB_Triple_Lookup`); an unknown name raises with
  # `Status::UnknownProfile`.
  def self.lookup(name : String) : Profile
    json = retry_once(JSON_CAP) do |buf, len_p|
      LibItb.triple_lookup(name, buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
    end
    Profile.from_json(String.new(json))
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

  # Registers *profile* under *name* so subsequent `Pipeline.new` /
  # `ITB.lookup` calls resolve it (`ITB_Triple_Register`). Every
  # field rule is validated by Go; a duplicate name fails with
  # `Status::ProfileExists`.
  def self.register(name : String, profile : Profile) : Nil
    check(LibItb.triple_register(name, profile.to_json))
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
