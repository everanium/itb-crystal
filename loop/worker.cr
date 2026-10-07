# The worker: its per-worker state, its fiber body (one warmup
# iteration, the warmup barrier, the main loop), one iteration, the
# session pump loop the stream shape drives, and the round-trip
# comparison that decides between a worker error and a data mismatch.

# Crystal-specific. `exit` unwinds through the at_exit handlers and
# flushes every registered IO; the data-mismatch path must not run any
# of that, so the raw process-termination entry is declared here and
# the evidence line is written and flushed before it is called.
lib LibLoopExit
  fun _exit(status : LibC::Int) : NoReturn
end

module Loop
  # Cipher surfaces the --shape flag selects.
  enum Shape
    Stream        # session pump: begin / write / read / end
    Message       # Single Message: one whole-buffer call
    StreamOneShot # stream surface, one whole-buffer call
    Both          # all three, rotating by iteration number
  end

  SHAPE_NAMES = ["stream", "message", "stream_one_shot", "both"]

  def self.shape_name(shape : Shape) : String
    SHAPE_NAMES[shape.value]
  end

  def self.parse_shape(s : String) : Shape?
    idx = SHAPE_NAMES.index(s)
    idx.nil? ? nil : Shape.new(idx)
  end

  # One worker's private state: its plaintext, its reusable output
  # buffers, its generator, its counters, and the error it stopped on.
  class Worker
    getter id : Int32
    getter run : RunState
    property plaintext : Bytes
    property payload_mode : PayloadMode
    property seeded : Bool
    property rng : UInt64

    # Allocation posture. The per-worker plaintext is allocated once
    # and held for the whole run (rotating mode refills it in place per
    # iteration); the pump accumulators and the drain slice live here
    # and are reused across iterations, grown only when an envelope
    # exceeds the size they were opened at; the message and one-shot
    # entries hand back a fresh slice per call, which is the posture
    # the binding already takes on its own cipher path. Under the
    # default fixed CSPRNG mode every worker's buffer is distinct, so
    # cross-worker data crossover is detectable; pattern modes trade
    # that property for content edge-case coverage.
    property wire : Bytes
    property wire_len : Int32
    property plain : Bytes
    property plain_len : Int32
    property scratch : Bytes

    # Counters read by the summary after the worker has returned.
    property iters : Int64
    property bytes_enc : Int64
    property bytes_dec : Int64
    property nanos_enc : Int64
    property nanos_dec : Int64

    property failed : Bool
    property error : String

    def initialize(@id : Int32, @run : RunState, payload : Int32,
                   @payload_mode : PayloadMode, @seeded : Bool, @rng : UInt64)
      @plaintext = Bytes.new(payload)
      @wire = Bytes.new(payload + payload // 4 + 131_072)
      @wire_len = 0
      @plain = Bytes.new(payload)
      @plain_len = 0
      @scratch = Bytes.new(PUMP_SLICE)
      @iters = 0_i64
      @bytes_enc = 0_i64
      @bytes_dec = 0_i64
      @nanos_enc = 0_i64
      @nanos_dec = 0_i64
      @failed = false
      @error = ""
    end

    # Records the worker's error text (first error wins) and requests a
    # stop of the whole run.
    def fail(text : String) : Nil
      unless @failed
        @error = text
        @failed = true
      end
      @run.stop.set(true)
    end

    # Crystal-specific. Appends a drained chunk to one of the worker's
    # two accumulators, growing it only when an envelope exceeds the
    # size it was opened at, and returns the new byte count.
    private def append(into : Symbol, chunk : Bytes, used : Int32) : Int32
      acc = into == :wire ? @wire : @plain
      if used + chunk.size > acc.size
        grown = Bytes.new(used + chunk.size)
        acc[0, used].copy_to(grown.to_unsafe, used)
        into == :wire ? (@wire = grown) : (@plain = grown)
        acc = grown
      end
      chunk.copy_to(acc.to_unsafe + used, chunk.size)
      used + chunk.size
    end

    # Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
    # and ITB drives the chunk loop internally; the C ABI has no reader
    # / writer entry, so the caller drives it: open a session, feed
    # slices of at most 1 MiB, drain whatever the session has produced
    # after every write (a read before end never blocks), end, then
    # drain until the session reports finished (after end, a read on an
    # empty spool blocks until the terminal bytes arrive). The whole
    # produced output lands in the worker's reusable accumulator. The
    # loop is written here rather than delegated to the binding's
    # drain_all convenience so it stands in the utility, at the same
    # place, in every language.
    private def pump(session : ITB::StreamSession, src : Bytes,
                     into : Symbol) : Nil
      used = 0
      stage = "StreamWrite"
      begin
        off = 0
        while off < src.size
          hi = Math.min(off + PUMP_SLICE, src.size)
          stage = "StreamWrite"
          session.write(src[off, hi - off])
          off = hi
          loop do
            stage = "StreamRead"
            n, _fin = session.read_into(@scratch)
            break if n == 0
            used = append(into, @scratch[0, n], used)
          end
        end
        stage = "StreamEnd"
        session.end_stream
        loop do
          stage = "StreamRead"
          n, fin = session.read_into(@scratch)
          used = append(into, @scratch[0, n], used) if n > 0
          break if fin
        end
      rescue e : ITB::Error
        into == :wire ? (@wire_len = 0) : (@plain_len = 0)
        raise PumpFailure.new(stage, e)
      end
      into == :wire ? (@wire_len = used) : (@plain_len = used)
      nil
    end

    # Runs one direction of the pump against the streaming Pipeline.
    private def pump_direction(encrypt : Bool, src : Bytes, into : Symbol) : Nil
      session : ITB::StreamSession
      begin
        session = encrypt ? @run.stream_pipe.encrypt_stream.as(ITB::StreamSession)
                          : @run.stream_pipe.decrypt_stream.as(ITB::StreamSession)
      rescue e : ITB::Error
        raise PumpFailure.new("StreamBegin", e)
      end
      begin
        pump(session, src, into)
      ensure
        session.free
      end
    end

    # Records a worker error for a failed cipher call. *stage* names
    # the session step for a pump failure and is empty for a
    # whole-buffer call, whose only step is the direction itself.
    private def cipher_fail(iter : Int64, shape : Shape, direction : String,
                            stage : String, e : ITB::Error) : Nil
      if stage.empty? || stage == direction
        fail("g#{@id} iter #{iter} shape=#{Loop.shape_name(shape)}: " \
             "#{direction}: #{Loop.detail(e)}")
      else
        fail("g#{@id} iter #{iter} shape=#{Loop.shape_name(shape)}: " \
             "#{direction}: #{stage}: #{Loop.detail(e)}")
      end
    end

    # One iteration. In order: refill the plaintext under rotating
    # mode; take the read lock; pick the surface; encrypt (timed);
    # decrypt (timed); compare the round-trip with the plaintext; bump
    # the counters; release the read lock. The whole round-trip runs
    # under the read side of the handle lock so a rekey or a blob
    # reopen (write side) never lands between an encrypt and its
    # decrypt.
    def iterate(iter : Int64) : Bool
      if @payload_mode == PayloadMode::Rotating
        ok, @rng = Loop.fill_payload(PayloadMode::Rotating, @seeded, @rng, @plaintext)
        unless ok
          fail("g#{@id} iter #{iter}: payload refill: csprng")
          return false
        end
      end

      @run.pipe_lock.lock_read
      begin
        iterate_locked(iter)
      ensure
        @run.pipe_lock.unlock_read
      end
    end

    # The part of an iteration that runs under the read lock: the
    # surface selection, both cipher directions, the comparison and
    # the counters.
    private def iterate_locked(iter : Int64) : Bool
      # Shape dispatch. message is one whole-buffer call on the Single
      # Message Pipeline; stream_one_shot is one whole-buffer call on
      # the streaming Pipeline (the C ABI's ITB_Triple_EncryptStream,
      # which routes to the same one-shot stream entry the Go
      # harness calls by name); stream opens a session on the same
      # streaming Pipeline and drives the chunk loop from here. Under
      # both the three rotate by iteration number so the session path
      # and the whole-buffer path alternate on one handle inside every
      # worker — the cross-path state-reuse hazard this harness exists
      # to catch.
      shape = @run.cfg.shape
      if shape == Shape::Both
        shape = case iter % 3
                when 0 then Shape::Stream
                when 1 then Shape::Message
                else        Shape::StreamOneShot
                end
      end

      got = Bytes.empty
      case shape
      when Shape::Stream
        t0 = Loop.now_ns
        begin
          pump_direction(true, @plaintext, :wire)
        rescue f : PumpFailure
          cipher_fail(iter, shape, "encrypt", f.stage, f.cause_error)
          return false
        end
        @nanos_enc += Loop.now_ns - t0
        t0 = Loop.now_ns
        begin
          pump_direction(false, @wire[0, @wire_len], :plain)
        rescue f : PumpFailure
          cipher_fail(iter, shape, "decrypt", f.stage, f.cause_error)
          return false
        end
        @nanos_dec += Loop.now_ns - t0
        got = @plain[0, @plain_len]
      when Shape::StreamOneShot
        begin
          t0 = Loop.now_ns
          wire = @run.stream_pipe.encrypt_stream_one_shot(@plaintext)
          @nanos_enc += Loop.now_ns - t0
        rescue e : ITB::Error
          cipher_fail(iter, shape, "encrypt", "", e)
          return false
        end
        begin
          t0 = Loop.now_ns
          got = @run.stream_pipe.decrypt_stream_one_shot(wire)
          @nanos_dec += Loop.now_ns - t0
        rescue e : ITB::Error
          cipher_fail(iter, shape, "decrypt", "", e)
          return false
        end
      else
        begin
          t0 = Loop.now_ns
          wire = @run.msg_pipe.encrypt_message(@plaintext)
          @nanos_enc += Loop.now_ns - t0
        rescue e : ITB::Error
          cipher_fail(iter, shape, "encrypt", "", e)
          return false
        end
        begin
          t0 = Loop.now_ns
          got = @run.msg_pipe.decrypt_message(wire)
          @nanos_dec += Loop.now_ns - t0
        rescue e : ITB::Error
          cipher_fail(iter, shape, "decrypt", "", e)
          return false
        end
      end

      # Failure model. A cipher call that returns a non-OK status is a
      # worker error: it is recorded, the run is asked to stop, the
      # other workers finish their in-flight iteration, and the error
      # is listed in the summary with the FAIL verdict. A round-trip
      # that returns OK with different bytes is a data mismatch: the
      # process terminates here, without summary or cleanup, because
      # the Pipeline state that produced the wrong bytes is the
      # evidence and nothing that runs afterwards may touch it.
      if got != @plaintext
        off = Loop.first_difference(@plaintext, got)
        Loop.err_line("DATA MISMATCH g#{@id} iter #{iter} " \
                      "shape=#{Loop.shape_name(shape)}: " \
                      "want #{@plaintext.size} bytes, got #{got.size} bytes, " \
                      "first difference at offset #{off}: " \
                      "want #{Loop.hex_window(@plaintext, off)} " \
                      "got #{Loop.hex_window(got, off)}")
        LibLoopExit._exit(3)
      end

      @iters += 1
      @bytes_enc += @plaintext.size.to_i64
      @bytes_dec += got.size.to_i64
      true
    end

    # The worker fiber body: one warmup iteration, the warmup barrier,
    # then the main loop until a stop is requested or the fixed
    # per-worker iteration budget (warmup included) is spent. A failing
    # warmup still passes both barriers so the launcher never waits on
    # a worker that has already given up.
    #
    # Concurrency mode. This binding runs shared-handle: every worker
    # is a fiber, the default execution context is resized to one
    # thread per worker plus one for the main fiber, and all workers
    # call into the same Pipeline handles under the read side of the
    # handle lock. The collector this runtime links suspends threads
    # with a signal whose handler runs on the current stack, which
    # inside a call into the shared library belongs to the library's
    # own runtime; the binding marks the calling thread as blocked for
    # the collector around every raw call (`GC_do_blocking`), so a
    # collection started by one worker while another is inside the
    # library scans that worker's own stack up to the point of entry
    # and never the library's. Without that mark two and three context
    # threads fault on every run; with it every capacity survives.
    def run_body : Nil
      ok = iterate(0_i64)
      @run.warmup_done.send(nil)
      @run.release.receive
      unless ok
        @run.worker_done
        return
      end

      iter = 1_i64
      loop do
        # Crystal-specific. A call into the shared library never yields,
        # and the event loop that fires the deadline timer runs only on
        # a scheduler thread that is looking for work — the context's
        # threads start on demand, so nothing guarantees an idle one.
        # The yield here hands the thread to its scheduler between
        # iterations, exactly where an in-flight iteration is allowed
        # to finish, and the fiber that enforces the deadline gets its
        # turn.
        Fiber.yield
        break if @run.cfg.iterations > 0 && iter >= @run.cfg.iterations
        break if @run.stop.get
        break unless iterate(iter)
        break unless Loop.maintenance(self, iter)
        iter += 1
      end
      @run.worker_done
    end
  end

  # Crystal-specific. The pump reports which session step failed
  # alongside the library's own exception; the two travel together so
  # the worker-error text can name the step.
  class PumpFailure < Exception
    getter stage : String
    getter cause_error : ITB::Error

    def initialize(@stage : String, @cause_error : ITB::Error)
      super(@stage)
    end
  end

  # First offset at which *a* and *b* differ; the shorter length when
  # one is a prefix of the other.
  def self.first_difference(a : Bytes, b : Bytes) : Int32
    n = Math.min(a.size, b.size)
    n.times { |i| return i if a[i] != b[i] }
    n
  end

  # Up to 16 bytes of *buf* from *off* as lowercase hex, or "-" when
  # *buf* has no bytes there.
  def self.hex_window(buf : Bytes, off : Int32) : String
    return "-" if off >= buf.size
    last = Math.min(off + 16, buf.size)
    String.build do |io|
      (off...last).each { |i| io << buf[i].to_s(16).rjust(2, '0') }
    end
  end
end
