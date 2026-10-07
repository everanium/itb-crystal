# The final summary in both renderings, and the two measurements it
# folds in that are not per-worker counters: the process resident set
# and the shared library's pool counters.

module Loop
  # The process's current resident set and its high-water mark in
  # bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
  # Both are zero on a platform without that file; the figures are
  # informational and never enter the verdict.
  def self.read_rss : {UInt64, UInt64}
    current = 0_u64
    peak = 0_u64
    begin
      File.each_line("/proc/self/status") do |line|
        next unless line.starts_with?("VmRSS:") || line.starts_with?("VmHWM:")
        rest = line[6..].strip
        j = 0
        while j < rest.size && rest[j].ascii_number?
          j += 1
        end
        next if j == 0
        kb = rest[0, j].to_u64 * 1024_u64
        line.starts_with?("VmRSS:") ? (current = kb) : (peak = kb)
      end
    rescue
      return {0_u64, 0_u64}
    end
    {current, peak}
  end

  # Pool counters. The shared library keeps process-wide monotonic
  # totals at every pool checkout of its cipher core: per hash-array
  # tier the starter width, checkouts, constructor misses, regrow
  # replacements and bytes allocated; for the scratch byte pool and the
  # parallax chunk pool the checkouts, constructor misses, regrows and
  # regrow bytes. Two snapshots bracketing the main loop are
  # differenced into per-run hit / miss figures that tell whether a
  # pool keeps its items warm between calls or evicts them across GC
  # cycles. The slot layout is read from the library: slot 0 carries
  # the tier count T, tier i occupies the five slots at 1 + 5*i, and
  # the two byte pools occupy the eight slots at 1 + 5*T; the buffer is
  # sized from the binding's length query, never from a constant.
  def self.pool_snapshot_alloc : Slice(Int64)?
    slots = ITB.pool_stats_len
    return nil if slots == 0
    Slice(Int64).new(slots)
  end

  def self.pool_snapshot_take(dst : Slice(Int64)) : Bool
    ITB.pool_stats(dst)
    true
  rescue ITB::Error
    false
  end

  # The differenced pool figures of one run.
  struct PoolDelta
    property tiers = 0
    property starter = [] of Int64
    property get = [] of Int64
    property fresh = [] of Int64
    property regrow = [] of Int64
    property new_bytes = [] of Int64
    property buf_get = 0_i64
    property buf_new = 0_i64
    property buf_regrow = 0_i64
    property buf_regrow_bytes = 0_i64
    property chunk_get = 0_i64
    property chunk_new = 0_i64
    property chunk_regrow = 0_i64
    property chunk_regrow_bytes = 0_i64
  end

  def self.pool_diff(r : RunState) : PoolDelta
    d = PoolDelta.new
    w = r.pool_warmup
    s = r.pool_steady
    return d if w.nil? || s.nil?
    return d if w.size < 9 || s.size != w.size
    tiers = s[0].to_i
    return d if tiers < 0 || tiers > 64 || 1 + 5 * tiers + 8 > s.size
    d.tiers = tiers
    tiers.times do |i|
      base = 1 + 5 * i
      d.starter << s[base + 0]
      d.get << s[base + 1] - w[base + 1]
      d.fresh << s[base + 2] - w[base + 2]
      d.regrow << s[base + 3] - w[base + 3]
      d.new_bytes << s[base + 4] - w[base + 4]
    end
    tail = 1 + 5 * tiers
    d.buf_get = s[tail + 0] - w[tail + 0]
    d.buf_new = s[tail + 1] - w[tail + 1]
    d.buf_regrow = s[tail + 2] - w[tail + 2]
    d.buf_regrow_bytes = s[tail + 3] - w[tail + 3]
    d.chunk_get = s[tail + 4] - w[tail + 4]
    d.chunk_new = s[tail + 5] - w[tail + 5]
    d.chunk_regrow = s[tail + 6] - w[tail + 6]
    d.chunk_regrow_bytes = s[tail + 7] - w[tail + 7]
    d
  end

  # Misses over checkouts as a percentage; zero when nothing was
  # checked out.
  def self.miss_percent(miss : Int64, get : Int64) : Float64
    return 0.0 if get <= 0
    100.0 * miss.to_f / get.to_f
  end

  # Writes *s* as a JSON string literal with the escapes JSON requires.
  def self.json_string(s : String) : String
    String.build do |io|
      io << '"'
      s.each_byte do |c|
        case c
        when '"'.ord  then io << "\\\""
        when '\\'.ord then io << "\\\\"
        when '\n'.ord then io << "\\n"
        when '\r'.ord then io << "\\r"
        when '\t'.ord then io << "\\t"
        else
          if c < 0x20
            io << "\\u" << c.to_s(16).rjust(4, '0')
          else
            io << c.unsafe_chr
          end
        end
      end
      io << '"'
    end
  end

  # The effective GC percentage as the runtime reports it: the query
  # form of the setter (a set-and-restore round trip inside the
  # library) so the field is the same whether the value came from the
  # flag, the environment, or the runtime default.
  def self.effective_gogc(flag : Int32) : Int32
    flag > 0 ? flag : ITB.set_gc_percent(-1)
  end

  # Output contract. Both renderings are shared with the Go harness and
  # every other binding's loop utility field for field: the same lines
  # in the same order, the same keys in the same order, floats with a
  # fixed number of decimals so the JSON is byte-identical across
  # implementations. The Go harness alone adds its runtime-internal
  # lines after rss: and its runtime-internal keys after
  # parallax_chunk_pool; nothing here reproduces them because nothing
  # they read is reachable through the C ABI.
  def self.final_summary(r : RunState, elapsed_ns : Int64) : Int32
    cfg = r.cfg
    total_iters = 0_i64
    total_enc = 0_i64
    total_dec = 0_i64
    nanos_enc = 0_i64
    nanos_dec = 0_i64
    errors = 0
    r.workers.each do |w|
      total_iters += w.iters
      total_enc += w.bytes_enc
      total_dec += w.bytes_dec
      nanos_enc += w.nanos_enc
      nanos_dec += w.nanos_dec
      errors += 1 if w.failed
    end

    # Throughput. Per-direction throughput divides the sum of every
    # worker's wall time in that direction by the worker count — the
    # equivalent single-stream wall time under N-way concurrency — so
    # each direction reports the aggregate rate it sustained rather
    # than collapsing to combined/2 (every iteration moves equal
    # encrypt and decrypt bytes, so a total-elapsed denominator would
    # give both directions the same figure). The combined rate keeps
    # total elapsed as the one-glance overall figure.
    avg_enc = nanos_enc > 0 ? nanos_enc // cfg.workers : 0_i64
    avg_dec = nanos_dec > 0 ? nanos_dec // cfg.workers : 0_i64

    rss_delta = r.rss_final.to_i64 - r.rss_warmup.to_i64
    rss_growth = r.rss_warmup > 0 ? 100.0 * rss_delta.to_f / r.rss_warmup.to_f : 0.0

    pd = pool_diff(r)
    pass = errors == 0
    gomaxprocs = ITB.set_gomaxprocs(0)
    stream_profile = r.has_stream ? r.stream_profile : ""
    msg_profile = r.has_msg ? r.msg_profile : ""

    if cfg.json_output
      j = String.build do |io|
        io << "{\"duration_seconds\":" << fmt_f("%.3f", elapsed_ns.to_f / 1e9)
        io << ",\"iterations\":" << total_iters
        io << ",\"per_worker_iterations\":["
        r.workers.each_with_index { |w, i| io << ',' if i > 0; io << w.iters }
        io << ']'
        io << ",\"bytes_encrypted\":" << total_enc
        io << ",\"bytes_decrypted\":" << total_dec
        io << ",\"encrypt_mb_per_sec\":" << fmt_f("%.1f", mb_per_sec(total_enc, avg_enc))
        io << ",\"decrypt_mb_per_sec\":" << fmt_f("%.1f", mb_per_sec(total_dec, avg_dec))
        io << ",\"combined_mb_per_sec\":" << fmt_f("%.1f", mb_per_sec(total_enc + total_dec, elapsed_ns))
        io << ",\"rekeys\":" << r.rekeys
        io << ",\"blob_cycles\":" << r.blob_cycles
        io << ",\"worker_errors\":["
        n = 0
        r.workers.each do |w|
          next unless w.failed
          io << ',' if n > 0
          n += 1
          io << json_string(w.error)
        end
        io << ']'
        io << ",\"verdict\":\"" << (pass ? "PASS" : "FAIL") << '"'
        io << ",\"shape\":\"" << shape_name(cfg.shape) << '"'
        io << ",\"stream_profile\":" << json_string(stream_profile)
        io << ",\"message_profile\":" << json_string(msg_profile)
        io << ",\"hash\":" << json_string(cfg.hash)
        io << ",\"mac\":" << json_string(cfg.mac)
        io << ",\"payload_bytes\":" << cfg.payload
        io << ",\"payload_mode\":\"" << payload_mode_name(cfg.payload_mode) << '"'
        io << ",\"seed\":" << cfg.seed
        io << ",\"key_bits\":" << cfg.key_bits
        io << ",\"nonce_bits\":" << cfg.nonce_bits
        io << ",\"blob_mode\":" << cfg.blob_mode
        io << ",\"drbg\":" << json_string(cfg.drbg)
        io << ",\"drbg_auto_tier\":" << json_string(ITB.drbg_auto_tier)
        io << ",\"chunk_size_bytes\":" << cfg.chunk_size
        io << ",\"barrier_fill\":" << cfg.barrier_fill
        io << ",\"parallax\":\"" << on_off(cfg.parallax) << '"'
        io << ",\"wrapper\":\"" << on_off(cfg.wrapper) << '"'
        io << ",\"goroutines_requested\":" << cfg.workers_requested
        io << ",\"goroutines\":" << cfg.workers
        io << ",\"concurrency\":\"" << CONCURRENCY_MODE << '"'
        io << ",\"gogc\":\"" << effective_gogc(cfg.gogc) << '"'
        io << ",\"memlimit_bytes\":" << cfg.memlimit
        io << ",\"gomaxprocs\":" << gomaxprocs
        io << ",\"microbatch_tiers\":" << json_string(policy_label("ITB_MICROBATCH_TIERS"))
        io << ",\"hashpool_starters\":" << json_string(policy_label("ITB_HASHPOOL_STARTERS"))
        io << ",\"rss_warmup_bytes\":" << r.rss_warmup
        io << ",\"rss_peak_bytes\":" << r.rss_peak
        io << ",\"rss_final_bytes\":" << r.rss_final
        io << ",\"rss_growth_percent\":" << fmt_f("%.2f", rss_growth)
        io << ",\"hash_pool_tiers\":["
        t = 0
        pd.tiers.times do |i|
          next if pd.starter[i] == 0
          io << ',' if t > 0
          t += 1
          io << "{\"tier\":" << i << ",\"starter\":" << pd.starter[i]
          io << ",\"get\":" << pd.get[i] << ",\"new\":" << pd.fresh[i]
          io << ",\"regrow\":" << pd.regrow[i] << ",\"new_bytes\":" << pd.new_bytes[i]
          io << ",\"miss_percent\":"
          io << fmt_f("%.2f", miss_percent(pd.fresh[i] + pd.regrow[i], pd.get[i])) << '}'
        end
        io << ']'
        io << ",\"buf_pool\":{\"get\":" << pd.buf_get << ",\"new\":" << pd.buf_new
        io << ",\"regrow\":" << pd.buf_regrow << ",\"regrow_bytes\":" << pd.buf_regrow_bytes
        io << ",\"miss_percent\":" << fmt_f("%.2f", miss_percent(pd.buf_regrow, pd.buf_get)) << '}'
        io << ",\"parallax_chunk_pool\":{\"get\":" << pd.chunk_get << ",\"new\":" << pd.chunk_new
        io << ",\"regrow\":" << pd.chunk_regrow << ",\"regrow_bytes\":" << pd.chunk_regrow_bytes
        io << ",\"miss_percent\":" << fmt_f("%.2f", miss_percent(pd.chunk_regrow, pd.chunk_get)) << '}'
        io << "}\n"
      end
      emit(STDOUT, j.to_slice)
      return pass ? 0 : 1
    end

    log_line("=== FINAL ===")
    log_line("  duration: " + human_duration((elapsed_ns + 500_000) // 1_000_000 * 1_000_000))
    parts = String.build do |io|
      r.workers.each_with_index { |w, i| io << " + " if i > 0; io << w.iters }
    end
    log_line("  iterations: #{parts} = #{total_iters} total")
    log_line("  throughput: encrypt #{human_rate(total_enc, avg_enc)}, " \
             "decrypt #{human_rate(total_dec, avg_dec)}, " \
             "combined #{human_rate(total_enc + total_dec, elapsed_ns)}")
    log_line("  bytes: #{human_bytes(total_enc)} encrypted, " \
             "#{human_bytes(total_dec)} decrypted")
    log_line("  data integrity: #{total_iters}/#{total_iters} PASS")
    log_line("  concurrency: #{CONCURRENCY_MODE}, workers #{cfg.workers} " \
             "(requested #{cfg.workers_requested})")
    log_line("  rss: warmup #{human_bytes(r.rss_warmup.to_i64)}, " \
             "peak #{human_bytes(r.rss_peak.to_i64)}, " \
             "final #{human_bytes(r.rss_final.to_i64)} " \
             "(delta #{human_bytes_signed(rss_delta)}, #{fmt_f("%.1f", rss_growth)}% growth)")
    pd.tiers.times do |i|
      next if pd.starter[i] == 0
      log_line("  hash pool tier #{i} (starter #{pd.starter[i]}): " \
               "get #{pd.get[i]}, miss #{pd.fresh[i] + pd.regrow[i]} " \
               "(new #{pd.fresh[i]} + regrow #{pd.regrow[i]}), " \
               "miss #{fmt_f("%.2f", miss_percent(pd.fresh[i] + pd.regrow[i], pd.get[i]))}%, " \
               "#{human_bytes(pd.new_bytes[i])} allocated")
    end
    log_line("  buf pool: get #{pd.buf_get}, regrow #{pd.buf_regrow} " \
             "(of which fresh #{pd.buf_new}), " \
             "miss #{fmt_f("%.2f", miss_percent(pd.buf_regrow, pd.buf_get))}%, " \
             "#{human_bytes(pd.buf_regrow_bytes)} regrown")
    log_line("  parallax chunk pool: get #{pd.chunk_get}, regrow #{pd.chunk_regrow} " \
             "(of which fresh #{pd.chunk_new}), " \
             "miss #{fmt_f("%.2f", miss_percent(pd.chunk_regrow, pd.chunk_get))}%, " \
             "#{human_bytes(pd.chunk_regrow_bytes)} regrown")
    log_line("  rekeys: #{r.rekeys}") if r.rekeys > 0
    log_line("  blob cycles: #{r.blob_cycles}") if r.blob_cycles > 0
    r.workers.each { |w| log_line("  ERROR: #{w.error}") if w.failed }
    if pass
      log_line("  verdict: PASS")
      return 0
    end
    log_line("  verdict: FAIL (errors=#{errors})")
    1
  end
end
