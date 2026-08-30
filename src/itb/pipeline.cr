# GC-managed wrapper around the Triple Pipeline handle.

module ITB
  # A Triple Pipeline session plus its exported blob bytes.
  #
  # The blob carries the session bundle the receiver feeds to
  # `Pipeline.new(profile, blob)`; `#rekey` refreshes it. Garbage
  # collection frees the handle (libitb zeroes key material
  # internally); `#free` releases it deterministically.
  #
  # Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  # chunk, so plaintext of verified chunks is released before a later
  # chunk can fail authentication.
  class Pipeline
    # Floor capacity for blob output buffers (Init / Rekey).
    BLOB_CAP = 65536

    # The exported session bundle bytes for the receiver side.
    getter blob : Bytes

    @handle : Handle

    # Constructs a Pipeline against the named profile.
    #
    # With `blob: nil` a fresh session is initialized (`ITB_Triple_Init`)
    # and `#blob` carries the exported bundle. With a blob the session
    # is reconstructed from it (`ITB_Triple_Open`); `masters` is nil to
    # use the blob-embedded masters, or `{perm, wrap}` to override
    # them. On a blob-buffer retry the Init re-runs and yields a fresh
    # session (the undersized attempt is closed by libitb before
    # returning).
    def initialize(profile : String, blob : Bytes? = nil,
                   opts : Opts = Opts.new,
                   masters : Tuple(Bytes, Bytes)? = nil)
      opts_s = opts.build
      handle = Handle.zero
      if blob.nil?
        raise ArgumentError.new("masters override requires a blob (open path)") unless masters.nil?
        @blob = ITB.retry_once(BLOB_CAP) do |buf, len_p|
          LibItb.triple_init(profile, opts_s,
            buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p,
            pointerof(handle))
        end
      else
        pm = Bytes.empty
        wm = Bytes.empty
        count = LibC::SizeT.zero
        if m = masters
          pm, wm = m
          raise ArgumentError.new("master override slices must be non-empty") if pm.empty? || wm.empty?
          count = LibC::SizeT.new(2)
        end
        rc = LibItb.triple_open(profile,
          blob.to_unsafe.as(Void*), LibC::SizeT.new(blob.size),
          opts_s,
          pm.to_unsafe.as(Void*), LibC::SizeT.new(pm.size),
          wm.to_unsafe.as(Void*), LibC::SizeT.new(wm.size),
          count, pointerof(handle))
        ITB.check(rc)
        @blob = blob.dup
      end
      @handle = handle
    end

    # Rotates the parallax + wrapper masters and refreshes `#blob`.
    # Must not run concurrently with cipher calls or open stream
    # sessions on the same Pipeline.
    def rekey(perm : Bytes, wrap : Bytes) : Nil
      @blob = ITB.retry_once(Math.max(BLOB_CAP, @blob.size)) do |buf, len_p|
        LibItb.triple_rekey(@handle,
          perm.to_unsafe.as(Void*), LibC::SizeT.new(perm.size),
          wrap.to_unsafe.as(Void*), LibC::SizeT.new(wrap.size),
          buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
      end
    end

    # Zeroes the Pipeline's key material and marks it closed.
    # Idempotent; subsequent cipher calls raise with
    # `Status::TripleClosed`.
    def close : Nil
      ITB.check(LibItb.triple_close(@handle))
    end

    # Single Message encrypt: one call, one self-contained wire.
    def encrypt_message(plain : Bytes) : Bytes
      cipher(plain) do |src, buf, len_p|
        LibItb.triple_encrypt_message(@handle,
          src.to_unsafe.as(Void*), LibC::SizeT.new(src.size),
          buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
      end
    end

    # :ditto:
    def encrypt_message(plain : String) : Bytes
      encrypt_message(plain.to_slice)
    end

    # Receive-side counterpart of `#encrypt_message`.
    def decrypt_message(wire : Bytes) : Bytes
      cipher(wire) do |src, buf, len_p|
        LibItb.triple_decrypt_message(@handle,
          src.to_unsafe.as(Void*), LibC::SizeT.new(src.size),
          buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
      end
    end

    # One-shot stream encrypt for callers holding the whole plaintext
    # in memory. For bounded-memory streaming use `#encrypt_stream`.
    def encrypt_stream_one_shot(plain : Bytes) : Bytes
      cipher(plain) do |src, buf, len_p|
        LibItb.triple_encrypt_stream(@handle,
          src.to_unsafe.as(Void*), LibC::SizeT.new(src.size),
          buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
      end
    end

    # Receive-side counterpart of `#encrypt_stream_one_shot`.
    def decrypt_stream_one_shot(wire : Bytes) : Bytes
      cipher(wire) do |src, buf, len_p|
        LibItb.triple_decrypt_stream(@handle,
          src.to_unsafe.as(Void*), LibC::SizeT.new(src.size),
          buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
      end
    end

    # Opens an incremental encrypt session (plaintext in, wire out).
    def encrypt_stream : StreamEncryptor
      StreamEncryptor.new(self)
    end

    # Opens an incremental decrypt session (wire in, plaintext out).
    def decrypt_stream : StreamDecryptor
      StreamDecryptor.new(self)
    end

    # Releases the Go-side handle deterministically (close + free).
    # Safe from any state; idempotent.
    def free : Nil
      return if @handle == 0
      LibItb.triple_free(@handle)
      @handle = Handle.zero
    end

    # GC finalizer — releases the Go-side handle. The status is
    # deliberately ignored on this path.
    def finalize
      free
    end

    # :nodoc:
    protected def handle : Handle
      @handle
    end

    def inspect(io : IO) : Nil
      # The blob bytes are elided — session-bundle material does not
      # belong in logs.
      io << "ITB::Pipeline(blob_len=" << @blob.size << ")"
    end

    def to_s(io : IO) : Nil
      inspect(io)
    end

    # Shared body for the four buffer-in / buffer-out cipher entries:
    # pre-allocate `max(131072, n * 5/4 + 131072)` and on
    # `BufferTooSmall` retry once with the exact size the FFI
    # reported (gated on the reported length strictly exceeding the
    # current capacity).
    private def cipher(src : Bytes, & : (Bytes, Bytes, LibC::SizeT*) -> Int32) : Bytes
      cap = Math.max(131072, src.size + src.size // 4 + 131072)
      buf = Bytes.new(cap)
      len = LibC::SizeT.zero
      rc = yield src, buf, pointerof(len)
      if rc == Status::BufferTooSmall.value && len > buf.size
        buf = Bytes.new(len)
        rc = yield src, buf, pointerof(len)
      end
      ITB.check(rc)
      buf[0, len]
    end
  end

  # :nodoc:
  # Single retry-once dispatch site for the variable-size blob output
  # buffers (Init / Rekey): pre-allocate `cap`, and on
  # `BufferTooSmall` retry once with the exact size the FFI reported
  # through the length out-param (gated on the reported length
  # strictly exceeding the current capacity).
  def self.retry_once(cap : Int32, & : (Bytes, LibC::SizeT*) -> Int32) : Bytes
    buf = Bytes.new(cap)
    len = LibC::SizeT.zero
    rc = yield buf, pointerof(len)
    if rc == Status::BufferTooSmall.value && len > buf.size
      buf = Bytes.new(len)
      rc = yield buf, pointerof(len)
    end
    check(rc)
    buf[0, len]
  end
end
