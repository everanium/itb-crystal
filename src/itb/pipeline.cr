# GC-managed wrapper around the Triple Pipeline handle.

module ITB
  # A Triple Pipeline session.
  #
  # `#save` exports the self-describing session blob the receiver
  # feeds to `Pipeline.load` / `Pipeline.load_f`; `#rekey` refreshes
  # it. Garbage collection frees the handle (libitb zeroes key
  # material internally); `#free` releases it deterministically.
  #
  # Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  # chunk, so plaintext of verified chunks is released before a later
  # chunk can fail authentication.
  class Pipeline
    # Floor capacity for blob output buffers (Init / Save / Rekey).
    BLOB_CAP = 65536

    @handle : Handle

    # Constructs a fresh Pipeline against the named profile
    # (`ITB_Triple_Init`); the session blob is available through
    # `#save`. On a blob-buffer retry the Init re-runs and yields a
    # fresh session (the undersized attempt is closed by libitb before
    # returning).
    def initialize(profile : String, opts : Opts = Opts.new)
      opts_s = opts.build
      handle = Handle.zero
      ITB.retry_once(BLOB_CAP) do |buf, len_p|
        LibItb.triple_init(profile, opts_s,
          buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p,
          pointerof(handle))
      end
      @handle = handle
    end

    # :nodoc:
    protected def initialize(@handle : Handle)
    end

    # Reconstructs a Pipeline from a blob produced by `#save` or
    # `#rekey` (`ITB_Triple_Load`). The blob's embedded profile
    # record is the sole structural source. `masters` is nil to use
    # the blob-embedded masters, or `{perm, wrap}` to override them.
    def self.load(blob : Bytes, masters : Tuple(Bytes, Bytes)? = nil) : Pipeline
      pm, wm, count = masters_view(masters)
      handle = Handle.zero
      rc = LibItb.triple_load(
        blob.to_unsafe.as(Void*), LibC::SizeT.new(blob.size),
        pm.to_unsafe.as(Void*), LibC::SizeT.new(pm.size),
        wm.to_unsafe.as(Void*), LibC::SizeT.new(wm.size),
        count, pointerof(handle))
      ITB.check(rc)
      new(handle)
    end

    # `Pipeline.load` for a blob stored in a file
    # (`ITB_Triple_LoadF`); the file is read inside the library. Same
    # masters semantics.
    def self.load_f(path : String, masters : Tuple(Bytes, Bytes)? = nil) : Pipeline
      pm, wm, count = masters_view(masters)
      handle = Handle.zero
      rc = LibItb.triple_load_f(path,
        pm.to_unsafe.as(Void*), LibC::SizeT.new(pm.size),
        wm.to_unsafe.as(Void*), LibC::SizeT.new(wm.size),
        count, pointerof(handle))
      ITB.check(rc)
      new(handle)
    end

    # Folds the optional master pair into the CAPI arity flag.
    private def self.masters_view(masters : Tuple(Bytes, Bytes)?) : Tuple(Bytes, Bytes, LibC::SizeT)
      if m = masters
        pm, wm = m
        raise ArgumentError.new("master override slices must be non-empty") if pm.empty? || wm.empty?
        {pm, wm, LibC::SizeT.new(2)}
      else
        {Bytes.empty, Bytes.empty, LibC::SizeT.zero}
      end
    end

    # The current self-describing session blob: the bytes `.new`
    # produced, the bytes `.load` re-marshalled, or the bytes of the
    # latest `#rekey`.
    def save : Bytes
      ITB.retry_once(BLOB_CAP) do |buf, len_p|
        LibItb.triple_save(@handle,
          buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size), len_p)
      end
    end

    # Writes `#save` to *path* inside the library with mode 0600; the
    # containing directory must exist.
    def save_f(path : String) : Nil
      ITB.check(LibItb.triple_save_f(@handle, path))
    end

    # Sets the worker cap for every subsequent cipher call. *n* is
    # clamped, never rejected: `n <= 0` selects auto (CPU count),
    # `n > 256` is treated as 256. Only the handle statuses raise.
    def max_workers(n : Int32) : Nil
      ITB.check(LibItb.triple_max_workers(@handle, n))
    end

    # Rotates the parallax + wrapper masters and returns the fresh
    # session blob (also available through `#save`). Must not run
    # concurrently with cipher calls or open stream sessions on the
    # same Pipeline.
    def rekey(perm : Bytes, wrap : Bytes) : Bytes
      ITB.retry_once(BLOB_CAP) do |buf, len_p|
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
      # Session-bundle material does not belong in logs; only the
      # handle state is rendered.
      io << "ITB::Pipeline(" << (@handle == 0 ? "freed" : "open") << ")"
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
