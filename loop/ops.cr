# The maintenance operations that mutate a live Pipeline handle
# between iterations: master rotation (--rekey-every) and blob reopen
# (--blob-cycle-every).

module Loop
  # Byte length of each fresh master drawn for a rotation. Matches the
  # size Init auto-generates for both the parallax and the wrapper
  # master.
  REKEY_MASTER_SIZE = 32

  # Master rotation. Rotates the parallax + wrapper masters on every
  # active Pipeline and retains the refreshed blob for subsequent blob
  # reopens. Masters are drawn fresh from the OS CSPRNG on every
  # rotation regardless of --seed (master rotation is pipeline keying,
  # not plaintext content); a disabled layer passes no bytes, which
  # Rekey ignores. The eight inner seeds and the MAC key are untouched
  # by design — Rekey targets only the two outer-layer master secrets.
  private def self.rekey_pipes(w : Worker, iter : Int64) : Bool
    r = w.run
    r.pipe_lock.write { rekey_pipes_locked(w, iter) }
  end

  # The rotation itself, under the write lock.
  private def self.rekey_pipes_locked(w : Worker, iter : Int64) : Bool
    r = w.run
    perm = Bytes.empty
    wrap = Bytes.empty

    if r.cfg.parallax
      perm = Bytes.new(REKEY_MASTER_SIZE)
      unless fill_random(perm)
        w.fail("g#{w.id} iter #{iter}: csprng: parallax master")
        return false
      end
    end
    if r.cfg.wrapper
      wrap = Bytes.new(REKEY_MASTER_SIZE)
      unless fill_random(wrap)
        w.fail("g#{w.id} iter #{iter}: csprng: wrapper master")
        return false
      end
    end

    if r.has_stream
      begin
        r.stream_blob = r.stream_pipe.rekey(perm, wrap)
      rescue e : ITB::Error
        w.fail("g#{w.id} iter #{iter}: Rekey(#{r.stream_profile}): #{detail(e)}")
        return false
      end
    end
    if r.has_msg
      begin
        r.msg_blob = r.msg_pipe.rekey(perm, wrap)
      rescue e : ITB::Error
        w.fail("g#{w.id} iter #{iter}: Rekey(#{r.msg_profile}): #{detail(e)}")
        return false
      end
    end
    r.rekeys += 1
    log_line("rekey: g#{w.id} iter #{iter} rotated parallax + wrapper masters " \
             "(rekey ##{r.rekeys})")
    true
  end

  # Blob reopen. Reopens every active Pipeline from its retained blob:
  # a fresh handle is loaded from the blob, the running handle is
  # freed, and the fresh one is swapped in, so every later iteration
  # round-trips through seeds and masters that survived a blob
  # crossing. The input is the blob Init or the latest Rekey handed
  # out, not a fresh Save: that is what a receiver holds, and reopening
  # from it proves the handed-out bytes rather than the live state. The
  # blob carries the Pipeline's full shape, so no override reaches the
  # reopen. On a Load failure the running handle stays and the failure
  # aborts the run.
  private def self.blob_cycle_pipes(w : Worker, iter : Int64) : Bool
    r = w.run
    r.pipe_lock.write { blob_cycle_pipes_locked(w, iter) }
  end

  # The reopen itself, under the write lock.
  private def self.blob_cycle_pipes_locked(w : Worker, iter : Int64) : Bool
    r = w.run
    if r.has_stream
      begin
        # The fresh handle is constructed into a local first, so a
        # raising Load leaves the running one in place; the old handle
        # is released only once the fresh one exists.
        fresh = ITB::Pipeline.load(r.stream_blob)
        r.stream_pipe.free
        r.stream_pipe = fresh
      rescue e : ITB::Error
        w.fail("g#{w.id} iter #{iter}: Load(#{r.stream_profile}): #{detail(e)}")
        return false
      end
    end
    if r.has_msg
      begin
        fresh = ITB::Pipeline.load(r.msg_blob)
        r.msg_pipe.free
        r.msg_pipe = fresh
      rescue e : ITB::Error
        w.fail("g#{w.id} iter #{iter}: Load(#{r.msg_profile}): #{detail(e)}")
        return false
      end
    end
    r.blob_cycles += 1
    log_line("blob-cycle: g#{w.id} iter #{iter} reopened from session blob " \
             "(cycle ##{r.blob_cycles})")
    true
  end

  # Handle mutation. Runs the periodic Pipeline-mutating operations
  # after a completed iteration: master rotation (--rekey-every) and
  # blob reopen (--blob-cycle-every). Both intervals count per-worker
  # iterations; the warmup iteration (iter 0) never triggers because
  # the worker loop calls this for iter >= 1 only. Rekey rewrites the
  # outer-layer keying of a live handle and a blob reopen replaces the
  # handle outright, so both take the write lock: in-flight cipher
  # calls drain first, and no encrypt is separated from its decrypt.
  # Returns false after recording the worker error.
  def self.maintenance(w : Worker, iter : Int64) : Bool
    cfg = w.run.cfg
    if cfg.rekey_every > 0 && iter % cfg.rekey_every == 0
      return false unless rekey_pipes(w, iter)
    end
    if cfg.blob_cycle_every > 0 && iter % cfg.blob_cycle_every == 0
      return false unless blob_cycle_pipes(w, iter)
    end
    true
  end
end
