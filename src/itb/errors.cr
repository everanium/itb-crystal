# Status codes and the error type shared by every fallible call.
#
# The numeric values mirror the libitb3 C ABI
# (cmd/cshared/internal/capi/errors.go) and are stable across
# releases.

module ITB
  # Integer status code returned by every libitb3 entry point.
  enum Status : Int32
    Ok               =  0
    BadHash          =  1
    BadKeyBits       =  2
    BadHandle        =  3
    BadInput         =  4
    BufferTooSmall   =  5
    EncryptFailed    =  6
    DecryptFailed    =  7
    SeedWidthMix     =  8
    BadMac           =  9
    MacFailure       = 10
    BlobMalformedRecipe = 11
    RecipePrimitiveUnknown = 12
    UnknownProfile   = 13
    Reserved14       = 14
    Reserved15       = 15
    Reserved16       = 16
    Reserved17       = 17
    BlobModeMismatch = 19
    BlobMalformed    = 20
    BlobVersionTooNew = 21
    BlobTooManyOpts  = 22
    StreamTruncated  = 23
    StreamAfterFinal = 24
    TripleClosed     = 25
    ProfileExists    = 26
    Internal         = 99
  end

  # The exception raised by every fallible binding call.
  #
  # `last_error` carries the `ITB_LastError` diagnostic captured
  # immediately after the failing call (process-global
  # last-write-wins — the message may belong to a different call
  # under concurrent FFI use; the status code is always
  # attributable).
  class Error < Exception
    # Normalized status (an unrecognized raw code maps to
    # `Status::Internal`; `status_code` keeps the raw value).
    getter status : Status
    # Raw integer status code as returned by libitb3.
    getter status_code : Int32
    # The `ITB_LastError` diagnostic ("" when none was recorded).
    getter last_error : String

    def initialize(@status : Status, @status_code : Int32, @last_error : String)
      super("itb: status=#{@status_code}: #{@last_error}")
    end

    # Builds an Error from a raw return code, pulling the
    # `ITB_LastError` diagnostic at construction time.
    def self.from_rc(rc : Int32) : Error
      new(Status.from_value?(rc) || Status::Internal, rc, ITB.read_last_error)
    end
  end

  # :nodoc:
  # Maps a raw FFI return code onto nil / raised `ITB::Error`.
  def self.check(rc : Int32) : Nil
    raise Error.from_rc(rc) unless rc == Status::Ok.value
  end

  # :nodoc:
  # Reads the `ITB_LastError` diagnostic (NUL-stripped). Returns ""
  # when no diagnostic is recorded. Never raises.
  def self.read_last_error : String
    # NULL/0 probe form is part of the ITB_LastError contract — it
    # reports the required capacity without writing.
    need = LibC::SizeT.zero
    rc = ITB.blocking(->{ LibItb3.last_error(Pointer(LibC::Char).null, LibC::SizeT.zero, pointerof(need)) })
    return "" unless rc == Status::Ok.value || rc == Status::BufferTooSmall.value
    return "" if need <= 1
    buf = Bytes.new(need)
    rc = ITB.blocking(->{ LibItb3.last_error(buf.to_unsafe.as(LibC::Char*), LibC::SizeT.new(buf.size), pointerof(need)) })
    return "" unless rc == Status::Ok.value
    String.new(buf[0, need - 1])
  end
end
