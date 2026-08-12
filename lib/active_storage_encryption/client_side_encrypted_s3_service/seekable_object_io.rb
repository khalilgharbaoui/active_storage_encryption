# frozen_string_literal: true

# A read-only, seekable IO over an object in an S3-compatible bucket. It exists because the
# encryption schemes in this gem are IO-agnostic: they need `read`, `pos`, `seek` and `size`,
# and they do not care whether those are served from a local file or from ranged GET requests.
# `EncryptedDiskService` hands them a `File`; this class is what lets a bucket take its place.
#
# Reads are buffered, because the schemes read in small increments (12 bytes of IV, 16 bytes of
# auth tag, then cipher blocks) and one HTTP request per such read would be unusable. The buffer
# window starts small and doubles - up to `maximum_read_ahead` - for as long as reads stay
# sequential, and resets the moment a read seeks elsewhere. That way a 1-byte `download_chunk`
# does not pull five megabytes, while a full download quickly reaches the large window it wants.
class ActiveStorageEncryption::ClientSideEncryptedS3Service::SeekableObjectIO
  INITIAL_READ_AHEAD_BYTES = 64 * 1024
  MAXIMUM_READ_AHEAD_BYTES = 5 * 1024 * 1024

  attr_reader :offset

  # @param object[Aws::S3::Object] the object to read from. Only `get(range:)` and `content_length` get used.
  # @param offset[Integer] the byte offset in the object which this IO presents as its own position 0
  # @param initial_read_ahead[Integer] the size of the first ranged GET, and of any GET after a seek
  # @param maximum_read_ahead[Integer] the largest ranged GET this IO will ever issue
  def initialize(object, offset: 0, initial_read_ahead: INITIAL_READ_AHEAD_BYTES, maximum_read_ahead: MAXIMUM_READ_AHEAD_BYTES)
    @object = object
    @offset = offset
    @initial_read_ahead = initial_read_ahead
    @maximum_read_ahead = maximum_read_ahead
    @read_ahead = initial_read_ahead
    @absolute_pos = offset
    @buffer = (+"").b
    @buffer_starts_at = 0
    @object_byte_size = nil
  end

  # Presents the bytes from `byte_offset` onwards as the start of this IO, and rewinds to it.
  # This is how the service skips its own ciphertext header before handing the IO to a scheme -
  # the scheme then computes its offsets from 0, as it would for a file containing only its own
  # ciphertext. Any buffered bytes are kept, so skipping the header costs no extra request.
  #
  # @param byte_offset[Integer] offset in the object to present as position 0
  # @return [self]
  def rebase(byte_offset)
    @offset = byte_offset
    @absolute_pos = byte_offset
    self
  end

  # @return [Integer] the number of readable bytes, excluding everything before the base offset
  def size
    object_byte_size - @offset
  end

  # @return [Integer] the read position, relative to the base offset
  def pos
    @absolute_pos - @offset
  end

  # @param to_offset[Integer] the offset to seek to, relative to the base offset
  # @param whence[Integer] one of IO::SEEK_SET, IO::SEEK_CUR or IO::SEEK_END
  # @return [Integer] 0, as IO#seek does
  def seek(to_offset, whence = IO::SEEK_SET)
    absolute_pos = case whence
    when IO::SEEK_SET then @offset + to_offset
    when IO::SEEK_CUR then @absolute_pos + to_offset
    when IO::SEEK_END then @offset + size + to_offset
    else raise ArgumentError, "Unsupported whence: #{whence.inspect}"
    end
    raise Errno::EINVAL, "Cannot seek before the start of the IO" if absolute_pos < @offset

    @absolute_pos = absolute_pos
    0
  end

  # Reads at most `n_bytes` bytes, following the semantics of IO#read: at EOF it returns
  # `nil` for a non-zero read length, and an empty String when reading to EOF.
  #
  # @param n_bytes[Integer,nil] how many bytes to read, or nil to read until EOF
  # @param outbuf[String,nil] a String to read into, as IO#read accepts
  # @return [String,nil]
  def read(n_bytes = nil, outbuf = nil)
    raise ArgumentError, "Negative length #{n_bytes} given" if n_bytes && n_bytes < 0

    read_bytes = (+"").b
    while n_bytes.nil? || read_bytes.bytesize < n_bytes
      fill_buffer_at(@absolute_pos) unless buffer_covers?(@absolute_pos)
      wanted = n_bytes ? (n_bytes - read_bytes.bytesize) : @buffer.bytesize
      available = @buffer.byteslice(@absolute_pos - @buffer_starts_at, wanted)
      break if available.nil? || available.empty?

      read_bytes << available
      @absolute_pos += available.bytesize
    end

    exhausted = read_bytes.empty? && n_bytes && n_bytes > 0
    return exhausted ? nil : read_bytes unless outbuf

    outbuf.clear
    exhausted ? nil : outbuf.replace(read_bytes)
  end

  private

  def buffer_covers?(absolute_pos)
    absolute_pos >= @buffer_starts_at && absolute_pos < (@buffer_starts_at + @buffer.bytesize)
  end

  def fill_buffer_at(absolute_pos)
    @read_ahead = if sequential_with_buffer?(absolute_pos)
      [@read_ahead * 2, @maximum_read_ahead].min
    else
      @initial_read_ahead
    end

    @buffer = (+"").b
    @buffer_starts_at = absolute_pos
    return if @object_byte_size && absolute_pos >= @object_byte_size

    last_byte_offset = absolute_pos + @read_ahead - 1
    last_byte_offset = [last_byte_offset, @object_byte_size - 1].min if @object_byte_size

    response = @object.get(range: "bytes=#{absolute_pos}-#{last_byte_offset}")
    @object_byte_size ||= total_byte_size_from(response.content_range)
    @buffer = (response.body.read || "").b
  rescue Aws::S3::Errors::InvalidRange
    # The object turned out to be shorter than the offset we asked for. This can only happen while
    # the size is still unknown, since we clamp the requested range once we do know it.
    @object_byte_size ||= @object.content_length
  end

  def sequential_with_buffer?(absolute_pos)
    @buffer.bytesize > 0 && absolute_pos == (@buffer_starts_at + @buffer.bytesize)
  end

  # The Content-Range response header of a ranged GET reads "bytes 0-63/1024", so a successful
  # ranged read also tells us the size of the whole object. Learning it this way spares us a HEAD
  # request, which matters because every scheme begins by reading the head of the ciphertext.
  def total_byte_size_from(content_range)
    content_range.to_s.split("/").last.to_i
  end

  def object_byte_size
    @object_byte_size ||= @object.content_length
  end
end
