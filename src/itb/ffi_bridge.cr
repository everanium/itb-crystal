# C ABI declarations for the libitb shared library (cmd/cshared).
#
# Every signature mirrors a prototype in dist/<os>-<arch>/libitb.h;
# C `size_t` / `uintptr_t` both map to `LibC::SizeT` (identical width
# on the supported 64-bit targets). Buffer parameters cross as
# (pointer, length) pairs in the header's argument order.
#
# Library resolution happens at link time through the backtick form of
# the ldflags annotation: src/itb/libitb_flags.sh implements the
# search order (`ITB_LIBITB_PATH` env -> walk-up to
# `dist/<os>-<arch>/libitb.<ext>` -> OS default loader path) and bakes
# the resolved directory into the binary as an RPATH, so the produced
# executables run without LD_LIBRARY_PATH.

module ITB
  # Go-side handle for Pipeline / stream-session / seed objects
  # (C `uintptr_t`).
  alias Handle = LibC::SizeT
end

@[Link(ldflags: "`#{__DIR__}/libitb_flags.sh`")]
lib LibItb
  # ── diagnostics / registry iteration ─────────────────────────────
  fun version = ITB_Version(out : LibC::Char*, cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun last_error = ITB_LastError(out : LibC::Char*, cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun hash_count = ITB_HashCount : LibC::Int
  fun hash_name = ITB_HashName(i : LibC::Int, out : LibC::Char*, cap : LibC::SizeT, out_len : LibC::SizeT*) : LibC::Int
  fun hash_width = ITB_HashWidth(i : LibC::Int) : LibC::Int

  # ── Go runtime knobs ─────────────────────────────────────────────
  fun set_memory_limit = ITB_SetMemoryLimit(limit : Int64) : Int64
  fun set_gc_percent = ITB_SetGCPercent(pct : LibC::Int) : LibC::Int

  # ── Triple Pipeline lifecycle ────────────────────────────────────
  fun triple_init = ITB_Triple_Init(profile : LibC::Char*, opts : LibC::Char*,
                                    blob_out : Void*, blob_cap : LibC::SizeT, blob_len : LibC::SizeT*,
                                    out_handle : LibC::SizeT*) : LibC::Int
  fun triple_open = ITB_Triple_Open(profile : LibC::Char*, blob : Void*, blob_len : LibC::SizeT,
                                    opts : LibC::Char*,
                                    perm_master : Void*, perm_master_len : LibC::SizeT,
                                    wrap_master : Void*, wrap_master_len : LibC::SizeT,
                                    masters_count : LibC::SizeT,
                                    out_handle : LibC::SizeT*) : LibC::Int
  fun triple_rekey = ITB_Triple_Rekey(handle : LibC::SizeT,
                                      perm_master : Void*, perm_master_len : LibC::SizeT,
                                      wrap_master : Void*, wrap_master_len : LibC::SizeT,
                                      blob_out : Void*, blob_cap : LibC::SizeT, blob_len : LibC::SizeT*) : LibC::Int
  fun triple_close = ITB_Triple_Close(handle : LibC::SizeT) : LibC::Int
  fun triple_free = ITB_Triple_Free(handle : LibC::SizeT) : LibC::Int
  fun triple_register_profile = ITB_Triple_RegisterProfile(name : LibC::Char*, opts : LibC::Char*) : LibC::Int

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
