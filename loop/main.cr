# Long-run stress harness. The loop utility holds one Pipeline handle
# per exercised cipher surface for minutes, hammers it with encrypt →
# decrypt → compare round-trips, rotates the outer masters and reopens
# the handle from its session blob on a schedule, and reports whether
# the process survived with every byte intact. It is the Crystal
# binding's counterpart of the Go harness under tools/loop: the same
# flags, the same round structure, the same summary in both renderings.
#
# The default shape is full production: the Streaming AEAD profile with
# parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner hash,
# 1024-bit keys, and the compile-in 512-bit nonce width, driven through
# a stream session for five minutes on 16 MiB plaintexts. The worker
# owns a CSPRNG-generated plaintext held for the whole run, so any
# cross-call state leakage inside the Pipeline surfaces as a data
# mismatch rather than cancelling out.
#
# A failure is one of two things. A cipher, rekey or load call that
# returns a non-OK status is a worker error: the run stops, the summary
# lists it, the verdict is FAIL and the exit code 1. A round-trip that
# returns without error but with different bytes is a data mismatch:
# the process terminates on the spot with exit code 3, printing the
# worker, the iteration and the first differing offset, and no summary
# — the state that produced the wrong bytes is the evidence. A crash
# inside the shared library or the host runtime has no exit code of its
# own here; surfacing it is what the utility is for.
#
# Usage:
#
#   ./loop --duration 5m --goroutines 3 --shape stream --hash areion512 \
#          --mac hmac-blake3 --payload-size 16MB --memlimit auto \
#          --parallax on --wrapper on
#
# Ctrl-C triggers a graceful shutdown: the in-flight iteration
# completes, then the partial summary prints.

require "../src/libitb3"
require "./size"
require "./payload"
require "./worker"
require "./ops"
require "./summary"

module Loop
  # --goroutines ceiling; the harness targets modest hosts and each
  # worker pins payload-sized buffers for the whole run.
  MAX_WORKERS = 10

  # The concurrency mode this binding implements, as the summary
  # reports it (shared-handle / independent-handles / single).
  CONCURRENCY_MODE = "shared-handle"

  # Largest slice fed to a stream session per write; the drain after
  # every write uses the same bound.
  PUMP_SLICE = 1 << 20

  # Profiles the shape-based pair is built against when --profile is
  # empty.
  DEFAULT_STREAM_PROFILE  = "streaming-aead-triple-mac-v1"
  DEFAULT_MESSAGE_PROFILE = "singlemsg-triple-mac-v1"

  # The primitive supplied for the parallax palette and the outer
  # cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
  # so it is sound outside the Interlocked Barrier, and it is the
  # closest relative of the AES-based inner primitive whose profiles
  # need this fill.
  KEYSTREAM_FILL_CIPHER = "aescmac"

  # The resolved command line.
  class Config
    property duration_ns = 0_i64       # run duration; ignored when iterations > 0
    property iterations = 0_i64        # per-worker count incl. warmup; 0 = duration-based
    property workers_requested = 0     # the --goroutines value as given
    property workers = 0               # the effective worker count
    property shape = Shape::Stream
    property hash = ""
    property mac = ""
    property payload = 0_i64           # bytes per iteration
    property memlimit = 0_i64          # resolved bytes; the effective limit once shaped
    property memlimit_auto = false     # --memlimit auto: cap only when the runtime has no limit
    property gogc = 0                  # 0 = leave the runtime default
    property parallax = true
    property wrapper = true

    property profile = ""              # empty = shape-based profile pair
    property key_bits = 0              # 0 = profile default
    property nonce_bits = 0            # 0 = profile default
    property blob_mode = 1             # container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    property chunk_size = 0_i64        # 0 = profile default
    property barrier_fill = 0          # 0 = profile default
    property drbg = ""                 # DRBG fill primitive; empty = profile default (auto tier)
    property gomaxprocs = 0            # 0 = inherit from the environment
    property rekey_every = 0_i64       # per-worker iterations between rotations; 0 = never
    property blob_cycle_every = 0_i64  # per-worker iterations between reopens; 0 = never
    property payload_mode = PayloadMode::Fixed
    property seed = 0_u64              # 0 = OS CSPRNG plaintexts
    property json_output = false
    property memprofile = ""           # empty = none
  end

  # The state the run shares: the Pipeline handles, the retained blobs,
  # the lock that keeps iterations clear of handle mutation, the stop
  # request, the warmup barrier, and the baselines the summary reads.
  class RunState
    property cfg : Config
    # Crystal-specific. A shape builds at most one of the two handles,
    # so each slot is nilable and the accessor below asserts the
    # presence the has_* flag already guarantees at every call site.
    property stream_pipe_slot : ITB::Pipeline? = nil
    property msg_pipe_slot : ITB::Pipeline? = nil
    property has_stream = false
    property has_msg = false
    property stream_profile = ""
    property msg_profile = ""

    # Handle mutation. Iterations hold the read side for their whole
    # encrypt -> decrypt -> compare; rekey and blob reopen take the
    # write side, so no cipher call is in flight while a handle's
    # keying changes or the handle itself is swapped, and no encrypt
    # is separated from its decrypt by either.
    property pipe_lock = Sync::RWLock.new

    # The blob Init handed out, replaced by every rekey; the input of
    # the next blob reopen. Guarded by pipe_lock.
    property stream_blob : Bytes = Bytes.empty
    property msg_blob : Bytes = Bytes.empty

    property rekeys = 0_i64
    property blob_cycles = 0_i64
    property workers = [] of Worker

    # Warmup barrier: every worker arrives at warmup_done after
    # iteration 0 and waits on release until main has taken the
    # baselines. The two channels are counted rendezvous points: main
    # receives one arrival per worker, then sends one release per
    # worker.
    property warmup_done = Channel(Nil).new
    property release = Channel(Nil).new
    property done = Channel(Nil).new

    # Set by the duration deadline, by a signal, or by a failing
    # worker; checked by every worker before it starts an iteration.
    property stop = Atomic(Bool).new(false)

    # The last returning worker stamps finish_ns under done_mu so
    # elapsed excludes the wake-up latency of the waiter.
    property done_mu = Mutex.new
    property start_ns = 0_i64
    property finish_ns = 0_i64

    # Baselines taken after the warmup barrier and at shutdown.
    property rss_warmup = 0_u64
    property rss_peak = 0_u64
    property rss_final = 0_u64
    property pool_warmup : Slice(Int64)? = nil
    property pool_steady : Slice(Int64)? = nil

    def initialize(@cfg : Config)
    end

    def stream_pipe : ITB::Pipeline
      @stream_pipe_slot.not_nil!
    end

    def stream_pipe=(p : ITB::Pipeline)
      @stream_pipe_slot = p
    end

    def msg_pipe : ITB::Pipeline
      @msg_pipe_slot.not_nil!
    end

    def msg_pipe=(p : ITB::Pipeline)
      @msg_pipe_slot = p
    end

    # Marks the worker returned; it stamps the finish instant itself so
    # the poll interval of the waiter never enters the elapsed time.
    # The stamps are ordered by the mutex, so the last worker to
    # return leaves the last instant.
    def worker_done : Nil
      @done_mu.synchronize { @finish_ns = Loop.now_ns }
      @done.send(nil)
    end
  end

  # ── Output ───────────────────────────────────────────────────────

  # Prints one prefixed status line to stdout. The text, its prefix and
  # its newline leave in one write: a routine that emitted them
  # separately would let another line land between the parts.
  def self.log_line(text : String) : Nil
    emit(STDOUT, ("[loop] " + text + "\n").to_slice)
  end

  # The stderr counterpart, under the same one-write rule.
  def self.err_line(text : String) : Nil
    emit(STDERR, ("loop: " + text + "\n").to_slice)
  end

  # Writes text to stderr verbatim, in one call (the usage block).
  def self.err_raw(text : String) : Nil
    emit(STDERR, text.to_slice)
  end

  # Writes *bytes* to *io* in one call and flushes. Every write of this
  # utility goes through here.
  #
  # Crystal-specific. SIGPIPE keeps its default disposition (restored
  # at the top of Loop.run), so a write from the main thread to a pipe
  # whose reader is gone ends the process on the spot. The runtime,
  # however, blocks every signal on the threads it starts for the
  # execution context, and a fiber may be running on any of them: from
  # such a thread the same write comes back as an error instead. The
  # error is answered the way the signal would have been — SIGPIPE is
  # sent to the process, where the main thread, which blocks nothing,
  # takes it with the default action, and the exit is by signal, code
  # 141, with nothing printed.
  def self.emit(io : IO::FileDescriptor, bytes : Bytes) : Nil
    io.write(bytes)
    io.flush
  rescue e : IO::Error
    raise e unless e.os_error == Errno::EPIPE
    LibC.kill(LibC.getpid, Signal::PIPE.value)
    LibLoopExit._exit(141)
  end

  def self.on_off(b : Bool) : String
    b ? "on" : "off"
  end

  # Renders a failed library call the way every implementation reports
  # one: the numeric status the binding's own surface carries, then the
  # sentence the library left behind.
  #
  # Crystal-specific. The exception's own message carries the same pair
  # under a different punctuation, so the two parts are taken from the
  # binding's own error fields — the status code and the sentence the
  # binding captured from the library at the moment the call failed —
  # rather than reshaped from that text.
  def self.detail(e : ITB::Error) : String
    "status #{e.status_code}: #{e.last_error}"
  end

  # Renders an encoder policy env value for the summary: the raw string
  # when set, "default" when the shipped ladder applies.
  def self.policy_label(name : String) : String
    v = ENV[name]?
    return "default" if v.nil?
    i = 0
    while i < v.size && (v[i] == ' ' || v[i] == '\t')
      i += 1
    end
    v = v[i..]
    v.empty? ? "default" : v
  end

  # ── Flags ────────────────────────────────────────────────────────

  # The raw flag values before validation.
  class RawFlags
    property barrier_fill = 0
    property blob_cycle_every = 0_i64
    property blob_mode = 1
    property chunk_size = "0"
    property drbg = ""
    property duration = "5m"
    property gogc = 0
    property gomaxprocs = 0
    property goroutines = 3
    property hash = "areion512"
    property iterations = 0_i64
    property json_output = false
    property key_bits = 0
    property mac = "hmac-blake3"
    property memlimit = "auto"
    property memprofile = ""
    property nonce_bits = 0
    property parallax = "on"
    property payload_mode = "fixed"
    property payload_size = "16MB"
    property profile = ""
    property rekey_every = 0_i64
    property seed = 0_u64
    property shape = "stream"
    property wrapper = "on"
  end

  # One command-line flag: its name, the type label the usage prints,
  # the help text, the rendered default suffix, and the assignment that
  # lands the raw value in its slot. Values are validated after the
  # whole line is parsed.
  record Flag,
    name : String,
    type_label : String,
    help : String,
    boolean : Bool,
    default_suffix : String,
    assign : Proc(String, Bool)

  # The flag table, in alphabetical order (the order the usage prints).
  # The default suffix is rendered from the slot while it still holds
  # its default, so the usage can never disagree with the value the
  # parse starts from.
  def self.flag_table(f : RawFlags) : Array(Flag)
    t = [] of Flag
    add_int = ->(name : String, get : -> Int32, set : Int32 -> Nil, help : String) do
      t << Flag.new(name, "int", help, false,
        get.call != 0 ? " (default #{get.call})" : "",
        ->(v : String) do
          n = v.to_i32?
          if n.nil?
            false
          else
            set.call(n)
            true
          end
        end)
    end
    add_i64 = ->(name : String, set : Int64 -> Nil, help : String) do
      t << Flag.new(name, "int", help, false, "",
        ->(v : String) do
          n = v.to_i64?
          if n.nil?
            false
          else
            set.call(n)
            true
          end
        end)
    end
    add_u64 = ->(name : String, set : UInt64 -> Nil, help : String) do
      t << Flag.new(name, "uint", help, false, "",
        ->(v : String) do
          if v.empty? || v[0] == '-'
            false
          else
            n = v.to_u64?
            if n.nil?
              false
            else
              set.call(n)
              true
            end
          end
        end)
    end
    add_str = ->(name : String, label : String, get : -> String, set : String -> Nil, help : String) do
      t << Flag.new(name, label, help, false,
        get.call.empty? ? "" : " (default \"#{get.call}\")",
        ->(v : String) { set.call(v); true })
    end
    add_bool = ->(name : String, set : Bool -> Nil, help : String) do
      t << Flag.new(name, "", help, true, "",
        ->(v : String) do
          case v
          when "true"
            set.call(true)
            true
          when "false"
            set.call(false)
            true
          else
            false
          end
        end)
    end

    add_int.call("barrier-fill", ->{ f.barrier_fill }, ->(v : Int32) { f.barrier_fill = v; nil },
      "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)")
    add_i64.call("blob-cycle-every", ->(v : Int64) { f.blob_cycle_every = v; nil },
      "reopen each pipeline from its session blob every N iterations per worker; 0 = never")
    add_int.call("blob-mode", ->{ f.blob_mode }, ->(v : Int32) { f.blob_mode = v; nil },
      "container floor sizing mode: 1 (per-region, default) | 2 (per-container)")
    add_str.call("chunk-size", "string", ->{ f.chunk_size }, ->(v : String) { f.chunk_size = v; nil },
      "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape")
    add_str.call("drbg", "string", ->{ f.drbg }, ->(v : String) { f.drbg = v; nil },
      "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)")
    add_str.call("duration", "duration", ->{ f.duration }, ->(v : String) { f.duration = v; nil },
      "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0")
    add_int.call("gogc", ->{ f.gogc }, ->(v : Int32) { f.gogc = v; nil },
      "GC trigger percentage; 0 = leave the runtime default")
    add_int.call("gomaxprocs", ->{ f.gomaxprocs }, ->(v : Int32) { f.gomaxprocs = v; nil },
      "Go runtime GOMAXPROCS override; 0 = inherit from the environment")
    add_int.call("goroutines", ->{ f.goroutines }, ->(v : Int32) { f.goroutines = v; nil },
      "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1")
    add_str.call("hash", "string", ->{ f.hash }, ->(v : String) { f.hash = v; nil },
      "inner ITB hash primitive name")
    add_i64.call("iterations", ->(v : Int64) { f.iterations = v; nil },
      "fixed per-worker iteration count; 0 = duration-based")
    add_bool.call("json-output", ->(v : Bool) { f.json_output = v; nil },
      "print the final summary as one compact JSON object instead of log lines")
    add_int.call("key-bits", ->{ f.key_bits }, ->(v : Int32) { f.key_bits = v; nil },
      "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)")
    add_str.call("mac", "string", ->{ f.mac }, ->(v : String) { f.mac = v; nil },
      "MAC primitive name")
    add_str.call("memlimit", "string", ->{ f.memlimit }, ->(v : String) { f.memlimit = v; nil },
      "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)")
    add_str.call("memprofile", "string", ->{ f.memprofile }, ->(v : String) { f.memprofile = v; nil },
      "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none")
    add_int.call("nonce-bits", ->{ f.nonce_bits }, ->(v : Int32) { f.nonce_bits = v; nil },
      "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)")
    add_str.call("parallax", "string", ->{ f.parallax }, ->(v : String) { f.parallax = v; nil },
      "parallax layer: on | off")
    add_str.call("payload-mode", "string", ->{ f.payload_mode }, ->(v : String) { f.payload_mode = v; nil },
      "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii")
    add_str.call("payload-size", "string", ->{ f.payload_size }, ->(v : String) { f.payload_size = v; nil },
      "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)")
    add_str.call("profile", "string", ->{ f.profile }, ->(v : String) { f.profile = v; nil },
      "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair")
    add_i64.call("rekey-every", ->(v : Int64) { f.rekey_every = v; nil },
      "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never")
    add_u64.call("seed", ->(v : UInt64) { f.seed = v; nil },
      "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts")
    add_str.call("shape", "string", ->{ f.shape }, ->(v : String) { f.shape = v; nil },
      "cipher surface to exercise: stream | message | stream_one_shot | both")
    add_str.call("wrapper", "string", ->{ f.wrapper }, ->(v : String) { f.wrapper = v; nil },
      "wrapper layer: on | off")
    t
  end

  def self.usage(table : Array(Flag)) : Nil
    text = String.build do |io|
      io << "Usage of loop:\n"
      table.each do |fl|
        io << "  -" << fl.name << (fl.type_label.empty? ? "" : " ") << fl.type_label << "\n"
        io << "    \t" << fl.help << fl.default_suffix << "\n"
      end
    end
    err_raw(text)
  end

  # Parses argv into the raw flag values. Accepts -name value,
  # --name value, -name=value and --name=value; a boolean flag takes no
  # value unless given as -name=true / -name=false. Returns 0, 1 for
  # -h / --help (usage printed), or -1 after printing the error.
  def self.parse_argv(argv : Array(String), table : Array(Flag)) : Int32
    i = 0
    while i < argv.size
      arg = argv[i]
      if arg.size < 2 || arg[0] != '-'
        err_line("unexpected positional arguments: [#{arg}]")
        return -1
      end
      name = arg[(arg[1] == '-' ? 2 : 1)..]
      if name == "h" || name == "help"
        usage(table)
        return 1
      end
      value = ""
      have_value = false
      if (eq = name.index('='))
        value = name[(eq + 1)..]
        have_value = true
        name = name[0, eq]
      end
      fl = table.find { |c| c.name == name }
      if fl.nil?
        err_line("flag provided but not defined: -#{name}")
        usage(table)
        return -1
      end
      unless have_value
        if fl.boolean
          value = "true"
        elsif i + 1 < argv.size
          i += 1
          value = argv[i]
        else
          err_line("flag needs an argument: -#{fl.name}")
          return -1
        end
      end
      unless fl.assign.call(value)
        err_line("invalid value \"#{value}\" for flag -#{fl.name}")
        return -1
      end
      i += 1
    end
    0
  end

  # Maps "on" / "off" to a bool; nil otherwise.
  def self.parse_on_off(v : String) : Bool?
    case v
    when "on"  then true
    when "off" then false
    else            nil
    end
  end

  # Whether *name* is in the shipped hash registry the binding
  # enumerates. The registry is the authority the flag validation
  # reads; reaching it any other way would reach past the binding.
  def self.hash_registered?(name : String) : Bool
    ITB.hash_names.includes?(name)
  rescue ITB::Error
    false
  end

  # Folds a keystream primitive into opts for any layer the named
  # profile leaves unfilled but the operator asked for.
  #
  # A profile built around a primitive that is safe only inside the
  # Interlocked Barrier ships with no parallax palette and no outer
  # cipher: both layers run outside the barrier, where that primitive
  # would stand bare, so the recipe leaves them unnamed rather than
  # naming a primitive that must not key them. Engaging either layer
  # therefore needs a keystream-capable primitive supplied from outside
  # the recipe; without it construction fails on a palette below its
  # minimum or an unnamed outer cipher, and the primitive that most
  # deserves stressing becomes the one that cannot be stressed with
  # those layers engaged.
  #
  # Overrides fold into the resolved record the blob carries, so the
  # receiver rebuilds the same shape from the blob alone.
  #
  # Crystal-specific. The binding decodes the record into a typed
  # value, so the unfilled state is an empty palette / outer-cipher
  # field rather than an absent JSON key.
  #
  # Returns 1 when a layer was filled, 0 when none needed it, -1 on a
  # lookup failure (message already printed).
  def self.fill_keystream_layers(name : String, opts : ITB::Opts,
                                 want_parallax : Bool, want_wrapper : Bool) : Int32
    begin
      record = ITB.lookup(name)
    rescue ITB::Error
      err_line("--profile \"#{name}\" is not a registered triple profile")
      return -1
    end
    filled = 0
    if want_parallax && record.palette.empty?
      opts.with_parallax_palette([KEYSTREAM_FILL_CIPHER, KEYSTREAM_FILL_CIPHER,
                                  KEYSTREAM_FILL_CIPHER])
      # A recipe that never carried a palette never carried a segment
      # size either, and the schedule rejects zero.
      opts.with_parallax_segment_size(4093) if record.segment == 0
      filled = 1
    end
    if want_wrapper && record.outer.empty?
      opts.with_outer_cipher(KEYSTREAM_FILL_CIPHER)
      filled = 1
    end
    filled
  end

  # Resolves a registered profile to the shape family its record's mode
  # exposes by reading the record through the binding's lookup: a mode
  # beginning with "streaming" exposes the stream surfaces, one
  # beginning with "singlemsg" the message surface, "blob-only" none.
  # Prints the validation message and returns nil on rejection.
  def self.profile_surface(name : String) : Shape?
    begin
      record = ITB.lookup(name)
    rescue ITB::Error
      err_line("--profile \"#{name}\" is not a registered triple profile")
      return nil
    end
    return Shape::Stream if record.mode.starts_with?("streaming")
    return Shape::Message if record.mode.starts_with?("singlemsg")
    err_line("--profile \"#{name}\" carries no cipher surface (blob-only mode)")
    nil
  end

  # Applies a --profile's surface to the requested shape: a
  # message-surface profile forces message; a stream-surface profile
  # keeps stream or stream_one_shot as requested and turns message or
  # both into stream.
  def self.narrow_shape(requested : Shape, surface : Shape) : Shape
    return Shape::Message if surface == Shape::Message
    requested == Shape::StreamOneShot ? Shape::StreamOneShot : Shape::Stream
  end

  # Builds the resolved config from argv. Returns {code, config}: code
  # is 0, 1 for help, or -1 after printing "loop: <message>" for the
  # first failing rule.
  def self.parse_flags(argv : Array(String)) : {Int32, Config}
    cfg = Config.new
    f = RawFlags.new
    table = flag_table(f)
    rc = parse_argv(argv, table)
    return {rc, cfg} if rc != 0

    ns = parse_duration(f.duration)
    if ns.nil? || ns <= 0
      err_line("--duration must be positive, got #{f.duration}")
      return {-1, cfg}
    end
    cfg.duration_ns = ns
    cfg.iterations = f.iterations
    if cfg.iterations < 0
      err_line("--iterations must be >= 0, got #{cfg.iterations}")
      return {-1, cfg}
    end
    if f.goroutines < 1 || f.goroutines > MAX_WORKERS
      err_line("--goroutines must be in 1..#{MAX_WORKERS}, got #{f.goroutines}")
      return {-1, cfg}
    end
    # Concurrency mode. This binding runs shared-handle: every worker
    # is a fiber on its own context thread and all of them call into
    # the same handles, so the effective count is the requested one —
    # see the note on Worker#run_body for the runtime property that
    # allows it.
    cfg.workers_requested = f.goroutines
    cfg.workers = f.goroutines
    shape = parse_shape(f.shape)
    if shape.nil?
      err_line("--shape must be stream | message | stream_one_shot | both, got \"#{f.shape}\"")
      return {-1, cfg}
    end
    cfg.shape = shape
    unless hash_registered?(f.hash)
      err_line("--hash \"#{f.hash}\" is not a registered hash primitive")
      return {-1, cfg}
    end
    cfg.hash = f.hash
    cfg.mac = f.mac # validated by Init: the C ABI enumerates no MAC names
    payload = parse_size(f.payload_size)
    if payload.nil?
      err_line("--payload-size: invalid size \"#{f.payload_size}\"")
      return {-1, cfg}
    end
    cfg.payload = payload
    if cfg.payload < 1
      err_line("--payload-size must be at least 1 byte")
      return {-1, cfg}
    end
    if f.memlimit == "auto"
      cfg.memlimit_auto = true
      cfg.memlimit = cfg.workers <= 3 ? (1_i64 << 30) : (256_i64 << 20)
    else
      lim = parse_size(f.memlimit)
      if lim.nil?
        err_line("--memlimit: invalid size \"#{f.memlimit}\"")
        return {-1, cfg}
      end
      cfg.memlimit = lim
    end
    cfg.gogc = f.gogc
    if cfg.gogc < 0
      err_line("--gogc must be >= 0, got #{cfg.gogc}")
      return {-1, cfg}
    end
    parallax = parse_on_off(f.parallax)
    if parallax.nil?
      err_line("--parallax must be on | off, got \"#{f.parallax}\"")
      return {-1, cfg}
    end
    cfg.parallax = parallax
    wrapper = parse_on_off(f.wrapper)
    if wrapper.nil?
      err_line("--wrapper must be on | off, got \"#{f.wrapper}\"")
      return {-1, cfg}
    end
    cfg.wrapper = wrapper
    cfg.profile = f.profile
    unless cfg.profile.empty?
      surface = profile_surface(cfg.profile)
      return {-1, cfg} if surface.nil?
      cfg.shape = narrow_shape(cfg.shape, surface)
    end
    cfg.key_bits = f.key_bits
    unless [0, 512, 1024, 2048].includes?(cfg.key_bits)
      err_line("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got #{cfg.key_bits}")
      return {-1, cfg}
    end
    cfg.nonce_bits = f.nonce_bits
    unless [0, 128, 256, 512].includes?(cfg.nonce_bits)
      err_line("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got #{cfg.nonce_bits}")
      return {-1, cfg}
    end
    cfg.blob_mode = f.blob_mode
    unless [1, 2].includes?(cfg.blob_mode)
      err_line("--blob-mode must be 1 (per-region) | 2 (per-container), got #{cfg.blob_mode}")
      return {-1, cfg}
    end
    cfg.barrier_fill = f.barrier_fill
    unless [0, 1, 2, 4, 8, 16, 32].includes?(cfg.barrier_fill)
      err_line("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got #{cfg.barrier_fill}")
      return {-1, cfg}
    end
    cfg.drbg = f.drbg # validated by Init: the C ABI enumerates no DRBG names
    chunk = parse_size(f.chunk_size)
    if chunk.nil?
      err_line("--chunk-size: invalid size \"#{f.chunk_size}\"")
      return {-1, cfg}
    end
    cfg.chunk_size = chunk
    cfg.gomaxprocs = f.gomaxprocs
    if cfg.gomaxprocs < 0
      err_line("--gomaxprocs must be > 0 when specified, got #{cfg.gomaxprocs}")
      return {-1, cfg}
    end
    cfg.rekey_every = f.rekey_every
    if cfg.rekey_every < 0
      err_line("--rekey-every must be >= 0, got #{cfg.rekey_every}")
      return {-1, cfg}
    end
    cfg.blob_cycle_every = f.blob_cycle_every
    if cfg.blob_cycle_every < 0
      err_line("--blob-cycle-every must be >= 0, got #{cfg.blob_cycle_every}")
      return {-1, cfg}
    end
    mode = parse_payload_mode(f.payload_mode)
    if mode.nil?
      err_line("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"#{f.payload_mode}\"")
      return {-1, cfg}
    end
    cfg.payload_mode = mode
    cfg.seed = f.seed
    cfg.json_output = f.json_output
    cfg.memprofile = f.memprofile
    {0, cfg}
  end

  # ── Pipelines ────────────────────────────────────────────────────

  # Prints the construction line with the recipe read back from the
  # blob the Pipeline handed out, not echoed from the flags: every
  # construction override is proven to have reached the library by the
  # value the receiver would see. Record values that are empty (a No
  # MAC profile's MAC, a mixed profile's single hash) print as "-".
  def self.log_pipeline_initialised(profile : String, blob : Bytes) : Nil
    begin
      record = ITB.inspect(blob)
    rescue e : ITB::Error
      log_line("pipeline initialised: profile=#{profile} blob=#{blob.size} bytes " \
               "(inspect: #{e.last_error})")
      return
    end
    line = "pipeline initialised: profile=#{profile} blob=#{blob.size} bytes " \
           "hash=#{record.hash.empty? ? "-" : record.hash} " \
           "key-bits=#{record.key_bits} " \
           "nonce-bits=#{record.nonce_bits || 0} " \
           "barrier-fill=#{record.barrier_fill || 0} " \
           "chunk-size=#{record.chunk} " \
           "mac=#{record.mac.empty? ? "-" : record.mac} " \
           "parallax=#{on_off(record.parallax)} " \
           "wrapper=#{on_off(record.wrapper)}"
    line += " container-mode=2" if record.container_mode == 2
    line += " drbg=#{record.drbg}" unless record.drbg.empty?
    log_line(line)
  end

  # Sets the inner blob's "mode" field of a wrap-layer session blob to
  # *target_mode* (1 = per-region, 2 = per-container) in place. The wrap
  # layer's profile record carries its own "mode" (a string), so the
  # search starts at the inner blob ("ib"); both shipped modes are one
  # digit wide, so the blob length does not change. Returns false when
  # the inner blob or its mode field is not found.
  def self.edit_inner_blob_mode(blob : Bytes, target_mode : Int32) : Bool
    find = ->(needle : Bytes, start : Int32) do
      (start..blob.size - needle.size).each do |i|
        return i if blob[i, needle.size] == needle
      end
      -1
    end
    ib_key = %("ib":{).to_slice
    mode_key = %("mode":).to_slice
    ib = find.call(ib_key, 0)
    return false if ib < 0
    mode = find.call(mode_key, ib + ib_key.size)
    return false if mode < 0
    at = mode + mode_key.size
    return false if at + 1 >= blob.size || blob[at] < '1'.ord || blob[at] > '2'.ord ||
                    (blob[at + 1] >= '0'.ord && blob[at + 1] <= '9'.ord)
    blob[at] = ('0'.ord + target_mode).to_u8
    true
  end

  # Constructs one Pipeline against *profile* with every flag-carried
  # override in the opts string (zero values included — the shared
  # library treats zero as "profile default"), then obtains the Init
  # blob once through save: the binding's init entry does not hand the
  # blob back, and the bytes are the ones Init produced. Later blob
  # reopens use the retained blob; save is never called again.
  def self.build_pipeline(cfg : Config, profile : String) : {ITB::Pipeline, Bytes}?
    opts = ITB::Opts.new
      .with_inner_hash(cfg.hash)
      .with_mac_name(cfg.mac)
      .with_parallax(cfg.parallax)
      .with_wrapper(cfg.wrapper)
      .with_key_bits(cfg.key_bits)
      .with_nonce_bits(cfg.nonce_bits)
      .with_barrier_fill(cfg.barrier_fill)
      .with_drbg(cfg.drbg)
      .with_chunk_size(cfg.chunk_size)
    unless cfg.profile.empty?
      filled = fill_keystream_layers(cfg.profile, opts, cfg.parallax, cfg.wrapper)
      return nil if filled < 0
      if filled > 0
        err_line("#{cfg.profile} leaves the requested keystream layers unnamed; " \
                 "#{KEYSTREAM_FILL_CIPHER} supplied for them")
      end
    end

    begin
      pipe = ITB::Pipeline.new(profile, opts)
    rescue e : ITB::Error
      err_line("Init(#{profile}): #{detail(e)}")
      return nil
    end
    begin
      blob = pipe.save
    rescue e : ITB::Error
      err_line("Save(#{profile}): #{detail(e)}")
      return nil
    end
    if cfg.blob_mode == 2
      # The sizing mode is not an Opts knob: the Init blob is edited and
      # the pipeline reopened from it, so the retained blob (the one
      # blob-cycle reopens from) carries the edited mode.
      unless edit_inner_blob_mode(blob, 2)
        err_line("rewrite blob mode: inner blob mode field not found")
        return nil
      end
      begin
        fresh = ITB::Pipeline.load(blob)
      rescue e : ITB::Error
        err_line("reload Mode 2 blob: #{detail(e)}")
        return nil
      end
      pipe.free
      pipe = fresh
    end
    log_pipeline_initialised(profile, blob)
    {pipe, blob}
  end

  # ── Run ──────────────────────────────────────────────────────────

  def self.run(argv : Array(String)) : Int32
    # Crystal-specific. This runtime ignores SIGPIPE and turns a write
    # to a closed stdout into an exception instead, which would end
    # the run with a stack trace and exit 1 rather than the way every
    # other implementation ends it. Restoring the signal's default
    # disposition before the first line is printed ends the process on
    # the spot, which is what a fleet driver expects; Loop.emit covers
    # the threads on which the runtime blocks the signal.
    Signal::PIPE.reset

    rc, cfg = parse_flags(argv)
    return 0 if rc == 1
    return 2 if rc != 0

    # Runtime shaping. A long run under allocation churn grows the Go
    # heap inside the shared library without bound unless a soft limit
    # paces the collector, so a limit is always in force: an explicit
    # --memlimit is set as given, and auto caps the heap only when the
    # runtime reports no limit at all (a limit already installed from
    # the environment is left standing). The GC percentage and
    # GOMAXPROCS are set only when their flag is non-zero — a zero flag
    # skips the setter rather than calling it with zero, because zero
    # is a real value to the GC-percent setter, and a call would
    # clobber whatever the environment installed. All of it lands
    # before any Pipeline exists so the baselines are taken under the
    # shaped runtime.
    if cfg.memlimit_auto
      ITB.set_memory_limit(cfg.memlimit) if ITB.set_memory_limit(-1_i64) == Int64::MAX
    else
      ITB.set_memory_limit(cfg.memlimit)
    end
    cfg.memlimit = ITB.set_memory_limit(-1_i64)
    ITB.set_gc_percent(cfg.gogc) if cfg.gogc > 0
    ITB.set_gomaxprocs(cfg.gomaxprocs) if cfg.gomaxprocs > 0

    # Crystal-specific. The default execution context is parallel with
    # a capacity of one; it is raised here to one thread per worker
    # plus one for the main fiber. The capacity is a ceiling: the
    # runtime starts a thread when runnable fibers are waiting, so the
    # workers spread over their threads as they are spawned, and the
    # deadline fiber is served at the yield every worker makes between
    # iterations (see Worker#run_body).
    Fiber::ExecutionContext.default.resize(cfg.workers + 1)

    log_line("start: duration=#{human_duration(cfg.duration_ns)} " \
             "iterations=#{cfg.iterations} goroutines=#{cfg.workers_requested} " \
             "workers=#{cfg.workers} concurrency=#{CONCURRENCY_MODE} " \
             "shape=#{shape_name(cfg.shape)} hash=#{cfg.hash} mac=#{cfg.mac} " \
             "payload=#{human_bytes(cfg.payload)} memlimit=#{human_bytes(cfg.memlimit)} " \
             "parallax=#{on_off(cfg.parallax)} wrapper=#{on_off(cfg.wrapper)}")
    log_line("overrides: profile=\"#{cfg.profile}\" key-bits=#{cfg.key_bits} " \
             "nonce-bits=#{cfg.nonce_bits} chunk-size=#{human_bytes(cfg.chunk_size)} " \
             "barrier-fill=#{cfg.barrier_fill} gomaxprocs=#{cfg.gomaxprocs} " \
             "rekey-every=#{cfg.rekey_every} blob-cycle-every=#{cfg.blob_cycle_every} " \
             "payload-mode=#{payload_mode_name(cfg.payload_mode)} seed=#{cfg.seed} " \
             "json-output=#{cfg.json_output}" \
             "#{cfg.blob_mode != 1 ? " blob-mode=#{cfg.blob_mode}" : ""}" \
             "#{cfg.drbg.empty? ? "" : " drbg=#{cfg.drbg}"}")
    log_line("policy: microbatch-tiers=#{policy_label("ITB_MICROBATCH_TIERS")} " \
             "hashpool-starters=#{policy_label("ITB_HASHPOOL_STARTERS")}")

    # Pipeline construction — one handle per exercised shape. stream
    # and stream_one_shot share the streaming handle.
    stream_profile = cfg.profile.empty? ? DEFAULT_STREAM_PROFILE : cfg.profile
    msg_profile = cfg.profile.empty? ? DEFAULT_MESSAGE_PROFILE : cfg.profile
    stream_pipe = nil
    stream_blob = Bytes.empty
    msg_pipe = nil
    msg_blob = Bytes.empty
    if cfg.shape.stream? || cfg.shape.stream_one_shot? || cfg.shape.both?
      built = build_pipeline(cfg, stream_profile)
      return 1 if built.nil?
      stream_pipe, stream_blob = built
    end
    if cfg.shape.message? || cfg.shape.both?
      built = build_pipeline(cfg, msg_profile)
      return 1 if built.nil?
      msg_pipe, msg_blob = built
    end

    r = RunState.new(cfg)
    r.stream_pipe_slot = stream_pipe
    r.msg_pipe_slot = msg_pipe
    r.has_stream = !stream_pipe.nil?
    r.has_msg = !msg_pipe.nil?
    r.stream_profile = stream_profile
    r.msg_profile = msg_profile
    r.stream_blob = stream_blob
    r.msg_blob = msg_blob

    cfg.workers.times do |i|
      w = Worker.new(i, r, cfg.payload.to_i, cfg.payload_mode, cfg.seed != 0,
        seed_worker(cfg.seed, i))
      ok, rng = fill_payload(cfg.payload_mode, w.seeded, w.rng, w.plaintext)
      unless ok
        err_line("payload fill: csprng")
        return 1
      end
      w.rng = rng
      r.workers << w
    end

    r.pool_warmup = pool_snapshot_alloc
    r.pool_steady = pool_snapshot_alloc
    if r.pool_warmup.nil? || r.pool_steady.nil?
      err_line("pool snapshot alloc failed")
      return 1
    end

    # Graceful stop. SIGINT / SIGTERM set a flag the deadline fiber
    # turns into the stop request the worker checks before starting an
    # iteration, so a signal interrupts nothing mid-call — the
    # in-flight encrypt / decrypt / compare completes, the worker
    # returns, and the partial summary prints with the verdict the
    # completed iterations earned.
    signal_seen = false
    Signal::INT.trap { signal_seen = true }
    Signal::TERM.trap { signal_seen = true }

    # Warmup barrier. The worker runs one iteration and waits; the
    # clock starts only once it has paid its first-call costs (pool
    # warm-up, lazy kernel dispatch, page faults on the payload
    # buffer), and the RSS and pool baselines taken here describe a
    # process that has already run the whole cipher path once.
    warmup_start = now_ns
    r.workers.each { |w| spawn { w.run_body } }
    cfg.workers.times { r.warmup_done.receive }
    r.rss_warmup, r.rss_peak = read_rss
    pool_snapshot_take(r.pool_warmup.not_nil!)
    warmup_ns = now_ns - warmup_start
    log_line("warmup: #{cfg.workers} workers x 1 iter completed in " \
             "#{human_duration((warmup_ns + 50_000_000) // 100_000_000 * 100_000_000)} " \
             "(baseline rss=#{human_bytes(r.rss_warmup.to_i64)})")

    # Open the gate; the duration timer is a deadline the waiter below
    # enforces in duration mode.
    r.start_ns = now_ns
    r.finish_ns = r.start_ns
    cfg.workers.times { r.release.send(nil) }

    # Wait for the workers, polling so the deadline and a signal are
    # both noticed promptly. The last worker to return stamps the
    # finish instant itself, so the poll interval never enters the
    # elapsed time.
    returned = 0
    while returned < cfg.workers
      select
      when r.done.receive
        returned += 1
      when timeout(10.milliseconds)
        r.stop.set(true) if signal_seen
        r.stop.set(true) if cfg.iterations == 0 && now_ns - r.start_ns >= cfg.duration_ns
      end
    end
    elapsed_ns = r.finish_ns - r.start_ns
    r.rss_final, r.rss_peak = read_rss
    pool_snapshot_take(r.pool_steady.not_nil!)

    unless cfg.memprofile.empty?
      begin
        ITB.write_heap_profile(cfg.memprofile)
        log_line("memprofile: heap profile written to #{cfg.memprofile}")
      rescue e : ITB::Error
        err_line("memprofile: #{e.last_error}")
      end
    end

    final_summary(r, elapsed_ns)
  end
end

exit(Loop.run(ARGV))
