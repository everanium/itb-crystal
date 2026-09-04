# Status codes and the error type shared by every fallible call.
#
# The numeric values mirror the libitb C ABI
# (cmd/cshared/internal/capi/errors.go) and are stable across
# releases.

module ITB
  # Integer status code returned by every libitb entry point.
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

    # Human-readable label for the status code.
    def label : String
      case self
      in .ok?                  then "ok"
      in .bad_hash?            then "unknown hash name"
      in .bad_key_bits?        then "invalid key bits"
      in .bad_handle?          then "invalid handle"
      in .bad_input?           then "invalid input"
      in .buffer_too_small?    then "output buffer too small"
      in .encrypt_failed?      then "encrypt failed"
      in .decrypt_failed?      then "decrypt failed"
      in .seed_width_mix?      then "seed width mismatch"
      in .bad_mac?             then "unknown MAC name or invalid MAC handle"
      in .mac_failure?         then "MAC verification failed"
      in .blob_malformed_recipe? then "blob profile record invalid"
      in .recipe_primitive_unknown?
        "blob profile record names a primitive absent from the local registries"
      in .unknown_profile?     then "unknown profile name"
      in .reserved14?, .reserved15?, .reserved16?, .reserved17?
        "reserved status"
      in .blob_mode_mismatch?  then "blob mode mismatch"
      in .blob_malformed?      then "malformed state blob"
      in .blob_version_too_new? then "blob version too new"
      in .blob_too_many_opts?  then "too many blob export opts"
      in .stream_truncated?    then "stream truncated before terminator"
      in .stream_after_final?  then "stream chunk after terminator"
      in .triple_closed?       then "Triple Pipeline is closed"
      in .profile_exists?      then "profile name already registered"
      in .internal?            then "internal error"
      end
    end
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
    # Raw integer status code as returned by libitb.
    getter status_code : Int32
    # The `ITB_LastError` diagnostic ("" when none was recorded).
    getter last_error : String

    def initialize(@status : Status, @status_code : Int32, @last_error : String)
      msg = "itb: status=#{@status_code} (#{@status.label})"
      msg += ": #{@last_error}" unless @last_error.empty?
      super(msg)
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
    rc = LibItb.last_error(Pointer(LibC::Char).null, LibC::SizeT.zero, pointerof(need))
    return "" unless rc == Status::Ok.value || rc == Status::BufferTooSmall.value
    return "" if need <= 1
    buf = Bytes.new(need)
    rc = LibItb.last_error(buf.to_unsafe.as(LibC::Char*), LibC::SizeT.new(buf.size), pointerof(need))
    return "" unless rc == Status::Ok.value
    String.new(buf[0, need - 1])
  end
end
