# C ABI declarations for the libitb3 shared library (cmd/cshared), and
# the collector guard every call into it runs under.
#
# Every signature mirrors a prototype in dist/<os>-<arch>/libitb3.h;
# C `size_t` / `uintptr_t` both map to `LibC::SizeT` (identical width
# on the supported 64-bit targets). Buffer parameters cross as
# (pointer, length) pairs in the header's argument order.
#
# Library resolution happens at link time through the backtick form of
# the ldflags annotation: src/itb/libitb3_flags.sh implements the
# search order (`ITB_LIBITB3_PATH` env -> walk-up to
# `dist/<os>-<arch>/libitb3.<ext>` -> OS default loader path) and bakes
# the resolved directory into the binary as an RPATH, so the produced
# executables run without LD_LIBRARY_PATH.
#
# The collector guard. The Boehm collector this runtime links stops the
# world by sending every registered thread a signal whose handler runs
# on whatever stack the thread is on, records the stack pointer it
# finds there, and later scans from that pointer up to the stack bottom
# the runtime registered for the thread. Inside a call into libitb3
# that stack pointer is not on the thread's own stack: the Go runtime
# runs an exported function on a goroutine stack, so the handler's
# frames land in Go-owned memory and the scan walks a range that is
# not a stack at all. With the default execution context holding a
# single thread nothing collects while the one thread is inside the
# library; the moment an application raises the context's capacity,
# any collection started by one thread while another is inside the
# library faults the process. A twelve-line Go library reproduces it
# without any of this project's code.
#
# `GC_do_blocking` is the collector's own answer for a thread that
# leaves managed code: it records the stack pointer on the thread's
# own stack before the call, and a world stop started during the call
# neither signals the thread nor waits for it — the stack is scanned
# from the recorded pointer, and the thread rejoins when the call
# returns. `ITB.blocking` wraps every raw call in the binding that way.
# Nothing inside the guarded region may allocate on the managed heap:
# the region holds the raw call and nothing else, every buffer sized
# and allocated by the caller before entry. The guard costs under a
# microsecond per entry, most of it the context save the collector
# performs on the way in.

module ITB
  # Go-side handle for Pipeline / stream-session / seed objects
  # (C `uintptr_t`).
  alias Handle = LibC::SizeT
end

@[Link(ldflags: "`#{__DIR__}/libitb3_flags.sh`")]
lib LibItb3
  # ── diagnostics ──────────────────────────────────────────────────
  fun version = ITB_Version(out : LibC::Char*, cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun drbg_auto_tier = ITB_DRBGAutoTier(out : LibC::Char*, cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun last_error = ITB_LastError(out : LibC::Char*, cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int

  # ── Go runtime knobs ─────────────────────────────────────────────
  fun set_memory_limit = ITB_SetMemoryLimit(limit : Int64) : Int64
  fun set_gc_percent = ITB_SetGCPercent(pct : LibC::Int) : LibC::Int
  fun set_gomaxprocs = ITB_SetGOMAXPROCS(n : LibC::Int) : LibC::Int
  fun write_heap_profile = ITB_WriteHeapProfile(path : LibC::Char*) : LibC::Int
  fun pool_stats_len = ITB_PoolStatsLen : LibC::Int
  fun pool_stats = ITB_PoolStats(out : Int64*, cap_elems : LibC::SizeT,
                                 out_len : LibC::SizeT*) : LibC::Int

  # ── Triple Pipeline lifecycle ────────────────────────────────────
  fun triple_init = ITB_Triple_Init(profile : LibC::Char*, opts : LibC::Char*,
                                    blob_out : Void*, blob_cap : LibC::SizeT, blob_len : LibC::SizeT*,
                                    out_handle : LibC::SizeT*) : LibC::Int
  fun triple_load = ITB_Triple_Load(blob : Void*, blob_len : LibC::SizeT,
                                    perm_master : Void*, perm_master_len : LibC::SizeT,
                                    wrap_master : Void*, wrap_master_len : LibC::SizeT,
                                    masters_count : LibC::SizeT,
                                    out_handle : LibC::SizeT*) : LibC::Int
  fun triple_load_f = ITB_Triple_LoadF(path : LibC::Char*,
                                       perm_master : Void*, perm_master_len : LibC::SizeT,
                                       wrap_master : Void*, wrap_master_len : LibC::SizeT,
                                       masters_count : LibC::SizeT,
                                       out_handle : LibC::SizeT*) : LibC::Int
  fun triple_save = ITB_Triple_Save(handle : LibC::SizeT,
                                    blob_out : Void*, blob_cap : LibC::SizeT, blob_len : LibC::SizeT*) : LibC::Int
  fun triple_save_f = ITB_Triple_SaveF(handle : LibC::SizeT, path : LibC::Char*) : LibC::Int
  fun triple_inspect = ITB_Triple_Inspect(blob : Void*, blob_len : LibC::SizeT,
                                          json_out : Void*, json_cap : LibC::SizeT, json_len : LibC::SizeT*) : LibC::Int
  fun triple_max_workers = ITB_Triple_MaxWorkers(handle : LibC::SizeT, n : LibC::Int) : LibC::Int
  fun triple_rekey = ITB_Triple_Rekey(handle : LibC::SizeT,
                                      perm_master : Void*, perm_master_len : LibC::SizeT,
                                      wrap_master : Void*, wrap_master_len : LibC::SizeT,
                                      blob_out : Void*, blob_cap : LibC::SizeT, blob_len : LibC::SizeT*) : LibC::Int
  fun triple_close = ITB_Triple_Close(handle : LibC::SizeT) : LibC::Int
  fun triple_free = ITB_Triple_Free(handle : LibC::SizeT) : LibC::Int

  # ── profile registry ─────────────────────────────────────────────
  fun triple_register = ITB_Triple_Register(name : LibC::Char*, profile_json : LibC::Char*) : LibC::Int
  fun triple_lookup = ITB_Triple_Lookup(name : LibC::Char*,
                                        json_out : Void*, json_cap : LibC::SizeT, json_len : LibC::SizeT*) : LibC::Int
  fun triple_profiles = ITB_Triple_Profiles(json_out : Void*, json_cap : LibC::SizeT, json_len : LibC::SizeT*) : LibC::Int
  fun triple_hash_names = ITB_Triple_HashNames(json_out : Void*, json_cap : LibC::SizeT, json_len : LibC::SizeT*) : LibC::Int

  # ── buffer-in / buffer-out cipher entries ────────────────────────
  fun triple_encrypt_message = ITB_Triple_EncryptMessage(handle : LibC::SizeT, src : Void*, src_len : LibC::SizeT,
                                                         out : Void*, out_cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun triple_decrypt_message = ITB_Triple_DecryptMessage(handle : LibC::SizeT, src : Void*, src_len : LibC::SizeT,
                                                         out : Void*, out_cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun triple_encrypt_stream = ITB_Triple_EncryptStream(handle : LibC::SizeT, src : Void*, src_len : LibC::SizeT,
                                                       out : Void*, out_cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun triple_decrypt_stream = ITB_Triple_DecryptStream(handle : LibC::SizeT, src : Void*, src_len : LibC::SizeT,
                                                       out : Void*, out_cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int

  # ── incremental stream sessions ──────────────────────────────────
  fun triple_encrypt_stream_begin = ITB_Triple_EncryptStreamBegin(pipe : LibC::SizeT, out_stream : LibC::SizeT*) : LibC::Int
  fun triple_decrypt_stream_begin = ITB_Triple_DecryptStreamBegin(pipe : LibC::SizeT, out_stream : LibC::SizeT*) : LibC::Int
  fun triple_stream_write = ITB_Triple_StreamWrite(stream : LibC::SizeT, src : Void*, src_len : LibC::SizeT) : LibC::Int
  fun triple_stream_end = ITB_Triple_StreamEnd(stream : LibC::SizeT) : LibC::Int
  fun triple_stream_read = ITB_Triple_StreamRead(stream : LibC::SizeT, out : Void*, out_cap : LibC::SizeT,
                                                 out_len : LibC::SizeT*, finished : LibC::Int*) : LibC::Int
  fun triple_stream_free = ITB_Triple_StreamFree(stream : LibC::SizeT) : LibC::Int
end

{% unless flag?(:gc_none) %}
  lib LibGC
    alias BlockingFn = Void* -> Void*
    fun do_blocking = GC_do_blocking(fn : BlockingFn, client_data : Void*) : Void*
  end
{% end %}

module ITB
  # :nodoc:
  # The stack slot a guarded call runs through: the call to make and
  # the value it returned. It lives in the caller's frame, which the
  # collector scans from the pointer `GC_do_blocking` recorded, so the
  # proc and everything it captured stay reachable for the whole
  # region.
  struct Blocking(T)
    property fn : Proc(T)
    property result : T

    def initialize(@fn : Proc(T))
      @result = T.zero
    end
  end

  # :nodoc:
  # Runs *fn* with the calling thread marked as blocked for the
  # collector (`GC_do_blocking`) and returns its value. Every raw
  # libitb3 call in the binding goes through here; *fn* must not
  # allocate on the managed heap. Under `-Dgc_none` there is no
  # collector to inform and the proc runs directly.
  def self.blocking(fn : Proc(T)) : T forall T
    {% if flag?(:gc_none) %}
      fn.call
    {% else %}
      slot = Blocking(T).new(fn)
      LibGC.do_blocking(->(data : Void*) : Void* {
        s = data.as(Blocking(T)*)
        s.value.result = s.value.fn.call
        Pointer(Void).null
      }, pointerof(slot).as(Void*))
      slot.result
    {% end %}
  end
end
