# Typed view of the Triple profile record — the JSON object that
# ITB_Triple_Inspect / ITB_Triple_Lookup emit, ITB_Triple_Register
# accepts, and the session blob carries in its wrap-layer.

require "json"

module ITB
  # A Triple Pipeline profile record.
  #
  # The record is a plain data holder plus a JSON codec over the
  # fourteen keys of the wire object (`name`, `mode`, `width`, `hash`,
  # `hashes`, `keybits`, `mac`, `tagstub`, `chunk`, `wrapper`,
  # `outer`, `parallax`, `palette`, `segment`). No semantic validation
  # happens on the Crystal side — every field rule (mode names, width
  # / hash agreement, key sizes, palette shape, reserved name
  # prefixes) is enforced by Go at `ITB.register` / `Pipeline.load`
  # time and surfaces as `ITB::Error`. Primitive / MAC / cipher names
  # are opaque strings.
  #
  # Encoding mirrors the Go codec: `mode`, `width`, `keybits`,
  # `wrapper`, `parallax` are always emitted; an empty string, zero
  # integer, or empty array is omitted. `hashes` carries either
  # nothing or exactly eight slot names in the order `[noise, lock,
  # data1, data2, data3, start1, start2, start3]`.
  class Profile
    # Registry handle (`name`); empty on an anonymous record.
    property name : String
    # Pipeline mode (`mode`), e.g. `streaming-aead`.
    property mode : String
    # Seed width in bits (`width`).
    property width : Int32
    # Uniform inner hash (`hash`); empty on a mixed profile.
    property hash : String
    # Eight-slot mixed constellation (`hashes`); empty on a uniform
    # profile.
    property hashes : Array(String)
    # Key material size in bits (`keybits`).
    property key_bits : Int32
    # MAC name (`mac`); empty on a No MAC profile.
    property mac : String
    # Tag stub size (`tagstub`); 0 when absent.
    property tag_stub : Int32
    # Streaming chunk size (`chunk`); 0 when absent.
    property chunk : Int32
    # Whether the wrapper layer is on (`wrapper`).
    property wrapper : Bool
    # Outer cipher name (`outer`); empty when absent.
    property outer : String
    # Whether the parallax layer is on (`parallax`).
    property parallax : Bool
    # Parallax palette (`palette`); empty when absent.
    property palette : Array(String)
    # Parallax segment size (`segment`); 0 when absent.
    property segment : Int32

    def initialize(@name = "", @mode = "", @width = 0, @hash = "",
                   @hashes = [] of String, @key_bits = 0, @mac = "",
                   @tag_stub = 0, @chunk = 0, @wrapper = false, @outer = "",
                   @parallax = false, @palette = [] of String, @segment = 0)
    end

    # Renders the record as the wire JSON object.
    def to_json : String
      JSON.build do |j|
        j.object do
          j.field "name", @name unless @name.empty?
          j.field "mode", @mode
          j.field "width", @width
          j.field "hash", @hash unless @hash.empty?
          j.field "hashes", @hashes unless @hashes.empty?
          j.field "keybits", @key_bits
          j.field "mac", @mac unless @mac.empty?
          j.field "tagstub", @tag_stub unless @tag_stub == 0
          j.field "chunk", @chunk unless @chunk == 0
          j.field "wrapper", @wrapper
          j.field "outer", @outer unless @outer.empty?
          j.field "parallax", @parallax
          j.field "palette", @palette unless @palette.empty?
          j.field "segment", @segment unless @segment == 0
        end
      end
    end

    # Decodes a wire JSON object into a record. Unknown keys are
    # ignored here; the Go side is the strict decoder.
    def self.from_json(json : String) : Profile
      m = JSON.parse(json)
      new(
        name: m["name"]?.try(&.as_s) || "",
        mode: m["mode"]?.try(&.as_s) || "",
        width: m["width"]?.try(&.as_i) || 0,
        hash: m["hash"]?.try(&.as_s) || "",
        hashes: strings(m["hashes"]?),
        key_bits: m["keybits"]?.try(&.as_i) || 0,
        mac: m["mac"]?.try(&.as_s) || "",
        tag_stub: m["tagstub"]?.try(&.as_i) || 0,
        chunk: m["chunk"]?.try(&.as_i) || 0,
        wrapper: m["wrapper"]?.try(&.as_bool) || false,
        outer: m["outer"]?.try(&.as_s) || "",
        parallax: m["parallax"]?.try(&.as_bool) || false,
        palette: strings(m["palette"]?),
        segment: m["segment"]?.try(&.as_i) || 0,
      )
    end

    # A copy of the record (arrays included).
    def dup : Profile
      Profile.from_json(to_json)
    end

    def ==(other : Profile) : Bool
      to_json == other.to_json
    end

    def to_s(io : IO) : Nil
      io << "ITB::Profile" << to_json
    end

    # :nodoc:
    # Decodes a JSON array of strings (the `ITB_Triple_Profiles`
    # output).
    def self.strings_from_json(json : String) : Array(String)
      strings(JSON.parse(json))
    end

    private def self.strings(v : JSON::Any?) : Array(String)
      return [] of String if v.nil?
      arr = v.as_a?
      return [] of String if arr.nil?
      arr.map(&.as_s)
    end
  end
end
