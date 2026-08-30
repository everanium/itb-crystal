# itb_eitb.cr — command-line demonstrator for the ITB Crystal binding.
#
# Subcommands:
#
#     eitb version                                library + binding versions
#     eitb hashes                                 shipped hash primitive roster
#     eitb profiles                               built-in Triple profile names
#     eitb encrypt <profile> <in-file> <out-file> Single Message encrypt
#     eitb decrypt <profile> <blob-hex> <in-file> <out-file>
#
# `encrypt` prints the session blob to stderr as hex; feed that hex
# back to `decrypt` on the receiving side.

require "../src/itb"

USAGE = <<-USAGE
usage: eitb version
       eitb hashes
       eitb profiles
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>
USAGE

def cmd_version : Nil
  puts "libitb #{ITB.version}"
  puts "itb-crystal #{ITB::VERSION}"
end

def cmd_hashes : Nil
  ITB.hashes.each_with_index do |h, i|
    printf("%2d  %-12s %d bits\n", i, h.name, h.width)
  end
end

def cmd_profiles : Nil
  ITB.profiles.each { |name| puts name }
end

# Profiles whose canonical name begins with "streaming-" route
# through the one-shot streaming buffered pair instead of the Single
# Message pair.
def streaming_profile?(profile : String) : Bool
  profile.starts_with?("streaming-")
end

# Recursively create the parent directory of *path* (mkdir -p).
def ensure_parent_dir(path : String) : Nil
  parent = File.dirname(path)
  Dir.mkdir_p(parent) unless parent.empty? || parent == "." || Dir.exists?(parent)
end

def cmd_encrypt(profile : String, infile : String, outfile : String) : Nil
  plain = File.read(infile).to_slice
  pipe = ITB::Pipeline.new(profile)
  wire = streaming_profile?(profile) ? pipe.encrypt_stream_one_shot(plain) : pipe.encrypt_message(plain)
  ensure_parent_dir(outfile)
  File.write(outfile, wire)
  STDERR.puts pipe.blob.hexstring
  puts "encrypted #{infile} -> #{outfile} (#{plain.size} -> #{wire.size} bytes)"
  pipe.free
end

def cmd_decrypt(profile : String, blob_hex : String, infile : String, outfile : String) : Nil
  blob = blob_hex.hexbytes
  wire = File.read(infile).to_slice
  pipe = ITB::Pipeline.new(profile, blob)
  plain = streaming_profile?(profile) ? pipe.decrypt_stream_one_shot(wire) : pipe.decrypt_message(wire)
  ensure_parent_dir(outfile)
  File.write(outfile, plain)
  puts "decrypted #{infile} -> #{outfile} (#{wire.size} -> #{plain.size} bytes)"
  pipe.free
end

args = ARGV
begin
  case {args[0]?, args.size}
  when {"version", 1}  then cmd_version
  when {"hashes", 1}   then cmd_hashes
  when {"profiles", 1} then cmd_profiles
  when {"encrypt", 4}  then cmd_encrypt(args[1], args[2], args[3])
  when {"decrypt", 5}  then cmd_decrypt(args[1], args[2], args[3], args[4])
  else
    STDERR.puts USAGE
    exit 2
  end
rescue ex : ITB::Error | IO::Error | ArgumentError
  STDERR.puts "eitb: #{ex.message}"
  exit 1
end
