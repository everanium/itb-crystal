# Integration spec suite for the ITB Crystal binding. Every case runs
# against the live libitb shared library resolved at link time.

require "spec"
require "../src/itb"

# Deterministic non-trivial payload (xorshift fill).
private def payload(n : Int32, seed : UInt64) : Bytes
  x = seed | 1
  Bytes.new(n) do
    x ^= x << 13
    x ^= x >> 7
    x ^= x << 17
    (x & 0xFF).to_u8
  end
end

# Runs the block and returns the raised ITB::Error, asserting the
# status is one of the expected set.
private def expect_status(expected : Array(ITB::Status), &) : ITB::Error
  ex = expect_raises(ITB::Error) { yield }
  expected.should contain(ex.status)
  ex.message.not_nil!.should_not be_empty
  ex
end

describe ITB do
  it "reports the library and binding versions" do
    ITB.version.should_not be_empty
    ITB::VERSION.should eq "0.3.1"
  end

  it "lists the hash registry in canonical order" do
    expected = [
      "areion256", "areion512", "blake2b256", "blake2b512",
      "blake2s", "blake3", "aescmac", "siphash24", "chacha20",
    ]
    got = ITB.hashes
    got.size.should eq expected.size
    got.zip(expected) do |row, name|
      row.name.should eq name
      row.width.should be > 0
    end
  end

  it "lists the shipped profiles" do
    got = ITB.profiles
    got.should_not be_empty
    [
      "singlemsg-triple-mac-v1",
      "singlemsg-triple-nomac-v1",
      "streaming-aead-triple-mac-v1",
      "streaming-noaead-triple-v1",
    ].each { |want| got.should contain(want) }
  end

  it "queries the Go runtime knobs" do
    # Negative values query without changing.
    ITB.set_memory_limit(-1_i64).should be_a Int64
    ITB.set_gc_percent(-1).should be_a Int32
  end

  it "round-trips a Single Message (singlemsg-triple-mac-v1)" do
    sender = ITB::Pipeline.new("singlemsg-triple-mac-v1")
    sender.blob.should_not be_empty
    receiver = ITB::Pipeline.new("singlemsg-triple-mac-v1", sender.blob)
    [1, 4 * 1024, 256 * 1024].each do |size|
      plain = payload(size, size.to_u64)
      wire = sender.encrypt_message(plain)
      wire.should_not eq plain
      receiver.decrypt_message(wire).should eq plain
    end
  end

  it "round-trips an incremental stream (streaming-noaead-triple-v1)" do
    sender = ITB::Pipeline.new("streaming-noaead-triple-v1")
    receiver = ITB::Pipeline.new("streaming-noaead-triple-v1", sender.blob)
    plain = payload(96 * 1024, 7_u64)

    # Encrypt incrementally: 8 KiB writes, then end + drain.
    enc = sender.encrypt_stream
    off = 0
    while off < plain.size
      n = Math.min(8192, plain.size - off)
      enc.write(plain[off, n])
      off += n
    end
    wire = enc.drain_all
    wire.should_not be_empty
    enc.free

    # Decrypt with pathological batch sizes (17-byte feed, 23-byte
    # drain) across chunk boundaries.
    dec = receiver.decrypt_stream
    off = 0
    while off < wire.size
      n = Math.min(17, wire.size - off)
      dec.write(wire[off, n])
      off += n
    end
    dec.end_stream
    back = IO::Memory.new
    loop do
      chunk, finished = dec.read(23)
      back.write(chunk)
      break if finished
    end
    dec.free
    back.to_slice.should eq plain
  end

  it "round-trips a large plaintext (pattern P1, > 1 MiB)" do
    sender = ITB::Pipeline.new("singlemsg-triple-nomac-v1")
    receiver = ITB::Pipeline.new("singlemsg-triple-nomac-v1", sender.blob)
    plain = payload(2 * 1024 * 1024 + 17, 3_u64)
    wire = sender.encrypt_message(plain)
    receiver.decrypt_message(wire).should eq plain
  end

  it "maps an unknown profile to BadInput" do
    ex = expect_status([ITB::Status::BadInput]) do
      ITB::Pipeline.new("no-such-profile")
    end
    ex.status_code.should eq ITB::Status::BadInput.value
  end

  it "maps an unknown opts key to BadInput" do
    # Typoed key (lowercase s) — Go rejects unknown keys; the binding
    # performs no validation of its own.
    expect_status([ITB::Status::BadInput]) do
      ITB::Pipeline.new("singlemsg-triple-mac-v1",
        opts: ITB::Opts.new.with_raw("chunksize", "4096"))
    end
  end

  it "fails authentication on a tampered wire" do
    sender = ITB::Pipeline.new("singlemsg-triple-mac-v1")
    receiver = ITB::Pipeline.new("singlemsg-triple-mac-v1", sender.blob)
    wire = sender.encrypt_message(payload(4096, 21_u64))
    tampered = wire.dup
    tampered[tampered.size // 2] ^= 0xFF
    expect_status([ITB::Status::MacFailure, ITB::Status::DecryptFailed]) do
      receiver.decrypt_message(tampered)
    end
  end

  it "maps a closed pipeline to TripleClosed" do
    pipe = ITB::Pipeline.new("singlemsg-triple-mac-v1")
    pipe.close
    pipe.close # idempotent
    expect_status([ITB::Status::TripleClosed]) do
      pipe.encrypt_message("payload".to_slice)
    end
  end

  it "refreshes the blob on rekey" do
    sender = ITB::Pipeline.new("singlemsg-triple-mac-v1")
    blob_before = sender.blob
    sender.rekey(payload(32, 5_u64), payload(32, 6_u64))
    sender.blob.should_not eq blob_before
    # The refreshed blob reconstructs a working receiver.
    receiver = ITB::Pipeline.new("singlemsg-triple-mac-v1", sender.blob)
    wire = sender.encrypt_message("post-rekey payload".to_slice)
    String.new(receiver.decrypt_message(wire)).should eq "post-rekey payload"
  end

  it "registers a custom profile and rejects a duplicate" do
    opts = ITB::Opts.new
      .with_raw("mode", "singlemsg-nomac")
      .with_raw("width", "256")
      .with_raw("innerHashes",
        "blake3,blake2s,areion256,blake2b256,chacha20,blake3,blake2s,areion256")
      .with_raw("keyBits", "1024")
      .with_raw("parallaxOn", "false")
      .with_raw("wrapperOn", "false")
    ITB.register_profile("crystal-binding-test-mixed", opts)
    sender = ITB::Pipeline.new("crystal-binding-test-mixed")
    receiver = ITB::Pipeline.new("crystal-binding-test-mixed", sender.blob)
    wire = sender.encrypt_message("custom profile".to_slice)
    String.new(receiver.decrypt_message(wire)).should eq "custom profile"
    expect_status([ITB::Status::ProfileExists]) do
      ITB.register_profile("crystal-binding-test-mixed", opts)
    end
  end

  it "encodes opts as a URL query string" do
    q = ITB::Opts.new
      .with_perm_master(Bytes[0xAB, 0x01])
      .with_parallax(true)
      .with_nonce_bits(512)
      .with_inner_hash("areion512")
      .with_parallax_palette(["aescmac", "chacha20", "blake3"])
      .with_raw("mode", "a b&c=d%")
      .build
    q.should eq "pm=ab01&withParallax=true&nonceBits=512&" \
                "innerHash=areion512&parallaxPalette=aescmac,chacha20,blake3&" \
                "mode=a%20b%26c%3Dd%25"
  end

  it "typed with_inner_hashes overrides the profile constellation" do
    # Base profile is a shipped single-primitive width-512 Single
    # Message profile; the per-call with_inner_hashes override
    # rebinds all 8 slots to an alternate width-512 constellation
    # for one Pipeline pair without touching the shipped registry.
    override = ITB::Opts.new.with_inner_hashes([
      "areion512", "blake2b512", "areion512", "blake2b512",
      "areion512", "blake2b512", "areion512", "blake2b512",
    ])
    sender = ITB::Pipeline.new("singlemsg-triple-mac-v1", opts: override)
    receiver = ITB::Pipeline.new(
      "singlemsg-triple-mac-v1", sender.blob, override)
    plain = payload(2048, 43_u64)
    receiver.decrypt_message(sender.encrypt_message(plain)).should eq plain
  end

  it "pins the parent pipeline while a stream session lives" do
    # No other reference to the Pipeline survives this Proc; the
    # session's @parent reference must keep the Go-side handle alive.
    sess = ->{
      pipe = ITB::Pipeline.new("streaming-noaead-triple-v1")
      pipe.encrypt_stream
    }.call
    GC.collect
    GC.collect
    sess.write("still alive after parent went out of scope".to_slice)
    sess.drain_all.should_not be_empty
    sess.free
  end
end
