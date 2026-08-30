# Incremental stream sessions over an open Pipeline.
#
# A session is a dumb byte pump: `StreamEncryptor` takes plaintext in
# through `#write` and yields wire through `#read` / `#drain_all`;
# `StreamDecryptor` is the mirror (wire in, plaintext out). All
# chunking, MAC, envelope, and wire-format decisions stay inside
# libitb. The `@parent` reference pins the parent Pipeline against
# garbage collection for the session's lifetime, so a session never
# outlives the handle it was begun on.

module ITB
  # Common behaviour of the two session directions.
  abstract class StreamSession
    # Default drain-buffer size for `#read` / `#drain_all`.
    READ_BUF = 1 << 20

    @handle : Handle
    # Pins the parent Pipeline against GC while the session lives.
    @parent : Pipeline
    @ended = false

    # :nodoc:
    protected def initialize(@parent : Pipeline, encrypt : Bool)
      handle = Handle.zero
      rc = if encrypt
             LibItb.triple_encrypt_stream_begin(@parent.handle, pointerof(handle))
           else
             LibItb.triple_decrypt_stream_begin(@parent.handle, pointerof(handle))
           end
      ITB.check(rc)
      @handle = handle
    end

    # Feeds `src` into the session. Blocks until the cipher chain
    # accepts the bytes; errors are sticky.
    def write(src : Bytes) : Nil
      ITB.check(LibItb.triple_stream_write(@handle,
        src.to_unsafe.as(Void*), LibC::SizeT.new(src.size)))
    end

    # :ditto:
    def write(src : String) : Nil
      write(src.to_slice)
    end

    # Signals end-of-input. Idempotent; `#write` after `#end_stream`
    # fails with `Status::BadInput`.
    def end_stream : Nil
      ITB.check(LibItb.triple_stream_end(@handle))
      @ended = true
    end

    # Drains up to `buf.size` produced bytes into `buf`; returns
    # `{bytes_read, finished}`. Partial drains are normal. Before
    # `#end_stream` an empty drain means "nothing available yet";
    # after it, an empty-spool read blocks until the terminal bytes
    # arrive or the session errors.
    def read_into(buf : Bytes) : Tuple(Int32, Bool)
      n = LibC::SizeT.zero
      fin = LibC::Int.zero
      ITB.check(LibItb.triple_stream_read(@handle,
        buf.to_unsafe.as(Void*), LibC::SizeT.new(buf.size),
        pointerof(n), pointerof(fin)))
      {n.to_i32, fin != 0}
    end

    # Allocating variant of `#read_into`: returns `{bytes, finished}`
    # with at most `max` bytes.
    def read(max : Int32 = READ_BUF) : Tuple(Bytes, Bool)
      buf = Bytes.new(max)
      n, fin = read_into(buf)
      {buf[0, n], fin}
    end

    # Calls `#end_stream` (if not yet called) and returns every
    # remaining output byte.
    def drain_all : Bytes
      end_stream unless @ended
      io = IO::Memory.new
      buf = Bytes.new(READ_BUF)
      loop do
        n, fin = read_into(buf)
        io.write(buf[0, n]) if n > 0
        break if fin
      end
      io.to_slice
    end

    # Cancels the session and releases the Go-side state
    # deterministically. Safe from any state; idempotent.
    def free : Nil
      return if @handle == 0
      LibItb.triple_stream_free(@handle)
      @handle = Handle.zero
    end

    # GC finalizer — cancels the session and frees the Go-side state.
    # The status is deliberately ignored on this path.
    def finalize
      free
    end
  end

  # Incremental encrypt session: plaintext in, wire out.
  class StreamEncryptor < StreamSession
    # :nodoc:
    def initialize(parent : Pipeline)
      super(parent, true)
    end
  end

  # Incremental decrypt session: wire in, plaintext out.
  class StreamDecryptor < StreamSession
    # :nodoc:
    def initialize(parent : Pipeline)
      super(parent, false)
    end
  end
end
