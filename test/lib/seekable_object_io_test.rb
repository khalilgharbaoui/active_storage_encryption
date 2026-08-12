# frozen_string_literal: true

require "test_helper"

class ActiveStorageEncryption::SeekableObjectIOTest < ActiveSupport::TestCase
  SeekableObjectIO = ActiveStorageEncryption::ClientSideEncryptedS3Service::SeekableObjectIO

  # Stands in for an Aws::S3::Object. The IO only uses `get(range:)` and `content_length`, and
  # this double records what it was asked for so that the tests can assert on the number and the
  # size of the requests - the buffering is the entire reason this class exists.
  class FakeObject
    Response = Struct.new(:body, :content_range)

    attr_reader :requested_ranges, :n_head_requests

    def initialize(bytes)
      @bytes = bytes.b
      @requested_ranges = []
      @n_head_requests = 0
    end

    def content_length
      @n_head_requests += 1
      @bytes.bytesize
    end

    def get(range:)
      first, last = range.match(/\Abytes=(\d+)-(\d+)\z/).captures.map(&:to_i)
      raise Aws::S3::Errors::InvalidRange.new(nil, "Range Not Satisfiable") if first >= @bytes.bytesize

      last = [last, @bytes.bytesize - 1].min
      @requested_ranges << (first..last)
      Response.new(StringIO.new(@bytes.byteslice(first, last - first + 1)), "bytes #{first}-#{last}/#{@bytes.bytesize}")
    end
  end

  setup do
    @bytes = Random.new(Minitest.seed).bytes(100 * 1024)
    @object = FakeObject.new(@bytes)
  end

  def test_reads_the_entire_object_sequentially
    io = SeekableObjectIO.new(@object)
    assert_equal @bytes, io.read
    assert_equal @bytes.bytesize, io.pos
  end

  def test_reads_in_increments_and_reassembles_the_object
    io = SeekableObjectIO.new(@object)
    reassembled = (+"").b
    while (chunk = io.read(1024))
      reassembled << chunk
    end
    assert_equal Digest::SHA256.hexdigest(@bytes), Digest::SHA256.hexdigest(reassembled)
  end

  def test_read_at_eof_follows_io_semantics
    io = SeekableObjectIO.new(@object)
    io.seek(@bytes.bytesize)

    assert_nil io.read(1)
    assert_equal "", io.read
    assert_equal "", io.read(0)
  end

  def test_read_into_a_buffer
    io = SeekableObjectIO.new(@object)
    buffer = (+"x" * 999)

    assert_same buffer, io.read(64, buffer)
    assert_equal @bytes.byteslice(0, 64), buffer

    io.seek(0, IO::SEEK_END)
    assert_nil io.read(1, buffer)
    assert_equal "", buffer
  end

  def test_seeks_from_every_whence
    io = SeekableObjectIO.new(@object)

    io.seek(10)
    assert_equal @bytes.byteslice(10, 4), io.read(4)

    io.seek(6, IO::SEEK_CUR)
    assert_equal @bytes.byteslice(20, 4), io.read(4)

    io.seek(-8, IO::SEEK_END)
    assert_equal @bytes.byteslice(@bytes.bytesize - 8, 8), io.read(8)

    assert_raises(Errno::EINVAL) { io.seek(-1) }
  end

  def test_random_access_reads_only_what_was_asked_for
    io = SeekableObjectIO.new(@object, initial_read_ahead: 1024, maximum_read_ahead: 8 * 1024)

    io.seek(50_000)
    assert_equal @bytes.byteslice(50_000, 10), io.read(10)

    assert_equal 1, @object.requested_ranges.length
    assert_equal (50_000..51_023), @object.requested_ranges.first
  end

  def test_read_ahead_grows_while_sequential_and_resets_after_a_seek
    io = SeekableObjectIO.new(@object, initial_read_ahead: 1024, maximum_read_ahead: 4096)

    io.read(4096) # Spans several windows, each one larger than the last
    assert_equal [1024, 2048, 4096], @object.requested_ranges.map(&:count).take(3)

    io.seek(70_000)
    io.read(1)
    assert_equal 1024, @object.requested_ranges.last.count
  end

  def test_learns_the_object_size_from_a_ranged_read_without_a_head_request
    io = SeekableObjectIO.new(@object)

    io.read(16)
    assert_equal @bytes.bytesize, io.size
    assert_equal 0, @object.n_head_requests
  end

  def test_asks_for_the_object_size_when_nothing_has_been_read_yet
    io = SeekableObjectIO.new(@object)

    assert_equal @bytes.bytesize, io.size
    assert_equal 1, @object.n_head_requests
  end

  def test_size_of_an_object_shorter_than_the_first_read
    short_object = FakeObject.new("hello")
    io = SeekableObjectIO.new(short_object)

    assert_equal "hello", io.read
    assert_equal 5, io.size
  end

  def test_rebase_presents_the_bytes_after_the_offset
    io = SeekableObjectIO.new(@object)
    io.read(5) # Reads a header, as the service does

    io.rebase(5)
    assert_equal 0, io.pos
    assert_equal @bytes.bytesize - 5, io.size
    assert_equal @bytes.byteslice(5, 4), io.read(4)

    io.seek(0)
    assert_equal @bytes.byteslice(5, 4), io.read(4)
  end

  def test_rebase_keeps_the_buffer_it_already_has
    io = SeekableObjectIO.new(@object)
    io.read(5)
    n_requests_after_header = @object.requested_ranges.length

    io.rebase(5)
    io.read(4)
    assert_equal n_requests_after_header, @object.requested_ranges.length
  end

  # The point of this IO is that the encryption schemes in this gem do not know or care where
  # their ciphertext comes from. This is that claim, tested: the scheme reads and seeks through
  # ranged requests exactly as it would through a file.
  def test_a_scheme_can_decrypt_and_seek_through_this_io
    encryption_key = Random.new(Minitest.seed).bytes(32)
    plaintext = Random.new(Minitest.seed).bytes(64 * 1024 + 7)
    scheme = ActiveStorageEncryption::EncryptedDiskService::V2Scheme.new(encryption_key)

    ciphertext = StringIO.new((+"").b)
    scheme.streaming_encrypt(into_ciphertext_io: ciphertext, from_plaintext_io: StringIO.new(plaintext))
    object = FakeObject.new(ciphertext.string)

    readback = (+"").b
    scheme.streaming_decrypt(from_ciphertext_io: SeekableObjectIO.new(object)) { |chunk| readback << chunk }
    assert_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(readback)

    range = 40_000..40_511
    assert_equal plaintext[range], scheme.decrypt_range(from_ciphertext_io: SeekableObjectIO.new(object), range: range)
  end
end
