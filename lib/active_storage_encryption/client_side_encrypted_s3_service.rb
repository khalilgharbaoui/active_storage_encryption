# frozen_string_literal: true

require "block_cipher_kit"
require "active_storage/service/s3_service"

module ActiveStorageEncryption
  # Stores ActiveStorage blobs on S3-compatible storage, encrypting them inside the application
  # process. Where `EncryptedS3Service` asks the storage provider to encrypt for us (SSE-C, so the
  # provider does hold the plaintext at the moment of the write), this service hands the provider
  # ciphertext and nothing else. The bytes on the wire and the bytes at rest are both encrypted
  # with a key the provider never sees.
  #
  # It reuses the encryption scheme of `EncryptedDiskService` rather than introducing a second one.
  # That is possible because the schemes only need an IO to read from - see `SeekableObjectIO`,
  # which turns ranged GET requests into the `read`/`seek`/`pos`/`size` they expect. So random
  # access - the property that lets a large video be scrubbed rather than downloaded whole -
  # survives the move from a local disk to a bucket.
  #
  # Configure it like so:
  #
  #   encrypted_s3:
  #     service: ClientSideEncryptedS3
  #     bucket: my-bucket
  #     region: eu-central-1
  #     private_url_policy: stream
  #
  # Two things behave differently from the SSE-C service, both of them consequences of the app
  # being the only party that can encrypt or decrypt:
  #
  # * A presigned URL can only ever yield ciphertext, so `private_url_policy: require_headers`
  #   is refused at configuration time. Use `stream` (through the controller in this gem, or
  #   through one of your own) or `disable`.
  # * Direct uploads from a browser cannot go to the bucket, since the browser has no key. They
  #   are routed to `EncryptedBlobsController` instead, exactly as `EncryptedDiskService` does:
  #   the app receives the plaintext, encrypts it, and puts it in the bucket.
  #
  # Bear in mind what streaming decryption can and cannot promise. GCM verifies its authentication
  # tag only once the whole ciphertext has been read, so a `download` that yields chunks to a block
  # will have yielded tampered plaintext before it raises, and `download_chunk` reads a range
  # without any authentication at all (see `V2Scheme`). If you need a guarantee that no altered
  # byte can reach a caller, read the whole blob with the non-block form of `download`, which
  # buffers and raises before returning anything.
  class ClientSideEncryptedS3Service < ActiveStorage::Service::S3Service
    include ActiveStorageEncryption::PrivateUrlPolicy

    autoload :SeekableObjectIO, __dir__ + "/client_side_encrypted_s3_service/seekable_object_io.rb"

    # Unlike a file on disk, an object in a bucket has no filename we can hang a scheme version
    # on, and asking the bucket for object metadata costs a request. So the ciphertext names its
    # own format: a magic string (which also tells us an object was written by this service at
    # all, rather than by a stock S3 service) followed by one byte of scheme version.
    CIPHERTEXT_MAGIC_BYTES = "ASEC"
    CIPHERTEXT_HEADER_BYTE_SIZE = CIPHERTEXT_MAGIC_BYTES.bytesize + 1

    # The version byte matches the scheme version of EncryptedDiskService, so that the same number
    # always means the same bytes on the wire regardless of where a blob is stored.
    SCHEME_VERSIONS = {
      2 => "ActiveStorageEncryption::EncryptedDiskService::V2Scheme"
    }
    CURRENT_SCHEME_VERSION = 2

    # This lets the Blob encryption key methods know that this
    # storage service _must_ use encryption
    def encrypted? = true

    def initialize(public: false, **options_for_s3_service_and_private_url_policy)
      raise ArgumentError, "encrypted files cannot be served via a public URL or a CDN" if public
      super
      if private_url_policy == :require_headers
        raise ArgumentError, "private_url_policy: require_headers is not available for #{self.class.name}, " \
          "because a presigned URL would serve ciphertext which the client has no key to decrypt"
      end
    end

    def service_name
      # ActiveStorage::Service::DiskService => Disk
      # Overridden because in Rails 8 this is "self.class.name.split("::").third.remove("Service")"
      self.class.name.split("::").last.remove("Service")
    end

    def upload(key, io, encryption_key:, checksum: nil, filename: nil, content_type: nil, disposition: nil, custom_metadata: {}, **)
      instrument :upload, key: key, checksum: checksum do
        # The checksum ActiveStorage gives us is of the plaintext, so it cannot be handed to S3 as
        # a Content-MD5 - S3 would be checking it against our ciphertext. We digest the plaintext
        # as it streams into the cipher instead, which verifies the same thing without reading the
        # object back out of the bucket afterwards.
        plaintext_io = checksum ? PlaintextChecksumIO.new(io) : io
        content_disposition = content_disposition_with(type: disposition, filename: filename) if disposition && filename

        # Build the scheme before opening the upload. An unusable encryption key must raise here,
        # where the caller can see the reason, rather than inside the block - the SDK would bury
        # it in a MultipartUploadError, and we would have left a dangling upload behind.
        scheme = scheme_for(CURRENT_SCHEME_VERSION, encryption_key)

        object_for(key).upload_stream(
          content_type: content_type,
          content_disposition: content_disposition,
          part_size: MINIMUM_UPLOAD_PART_SIZE,
          metadata: custom_metadata,
          **upload_options
        ) do |ciphertext_io|
          ciphertext_io.binmode
          ciphertext_io.write(ciphertext_header)
          scheme.streaming_encrypt(into_ciphertext_io: ciphertext_io, from_plaintext_io: plaintext_io)
        end

        ensure_integrity_of(key, checksum, plaintext_io) if checksum
      end
    end

    def download(key, encryption_key:, &block)
      if block_given?
        instrument :streaming_download, key: key do
          stream(key, encryption_key, &block)
        end
      else
        instrument :download, key: key do
          (+"").b.tap do |buf|
            stream(key, encryption_key) { |chunk| buf << chunk }
          end
        end
      end
    end

    def download_chunk(key, range, encryption_key:)
      instrument :download_chunk, key: key, range: range do
        open_ciphertext(key, encryption_key) do |ciphertext_io, scheme|
          scheme.decrypt_range(from_ciphertext_io: ciphertext_io, range: inclusive(range))
        end
      end
    end

    def compose(source_keys, destination_key, source_encryption_keys:, encryption_key:, filename: nil, content_type: nil, disposition: nil, custom_metadata: {})
      if source_keys.length != source_encryption_keys.length
        raise ArgumentError, "With #{source_keys.length} keys to compose there should be exactly as many source_encryption_keys, but got #{source_encryption_keys.length}"
      end
      content_disposition = content_disposition_with(type: disposition, filename: filename) if disposition && filename
      scheme = scheme_for(CURRENT_SCHEME_VERSION, encryption_key)

      object_for(destination_key).upload_stream(
        content_type: content_type,
        content_disposition: content_disposition,
        part_size: MINIMUM_UPLOAD_PART_SIZE,
        metadata: custom_metadata,
        **upload_options
      ) do |ciphertext_io|
        ciphertext_io.binmode
        ciphertext_io.write(ciphertext_header)
        scheme.streaming_encrypt(into_ciphertext_io: ciphertext_io) do |plaintext_writable|
          source_keys.zip(source_encryption_keys).each do |(source_key, source_encryption_key)|
            stream(source_key, source_encryption_key) { |chunk| plaintext_writable.write(chunk) }
          end
        end
      end
    end

    def url_for_direct_upload(key, expires_in:, content_type:, content_length:, checksum:, encryption_key:, custom_metadata: {})
      # A browser has no encryption key, so a PUT straight to the bucket would store plaintext.
      # The upload goes to this gem's own controller instead, which encrypts it on the way in.
      instrument :url, key: key do |payload|
        upload_token = ActiveStorage.verifier.generate(
          {
            key: key,
            content_type: content_type,
            content_length: content_length,
            encryption_key_sha256: Digest::SHA256.base64digest(encryption_key),
            checksum: checksum,
            service_name: name
          },
          expires_in: expires_in,
          purpose: :encrypted_put
        )

        # Unlike the DiskService, an S3 service has no url_options of its own to build absolute
        # URLs from - the ones ActiveStorage sets for the current request are what we have.
        url_options = ActiveStorage::Current.url_options
        raise ArgumentError, "Cannot generate a direct upload URL because ActiveStorage::Current.url_options is not set" if url_options.blank?

        url_helpers = ActiveStorageEncryption::Engine.routes.url_helpers
        url_helpers.encrypted_blob_put_url(upload_token, **url_options).tap do |generated_url|
          payload[:url] = generated_url
        end
      end
    end

    def headers_for_direct_upload(key, content_type:, encryption_key:, checksum:, **)
      {
        "Content-Type" => content_type,
        "x-active-storage-encryption-key" => Base64.strict_encode64(encryption_key),
        "content-md5" => checksum
      }
    end

    def headers_for_private_download(key, **)
      # Nothing to send: the bytes in the bucket are of no use without the key, and the key
      # never leaves the application.
      {}
    end

    private

    def ciphertext_header
      (CIPHERTEXT_MAGIC_BYTES + CURRENT_SCHEME_VERSION.chr).b
    end

    def scheme_for(version, encryption_key)
      scheme_class_name = SCHEME_VERSIONS.fetch(version) do
        raise ActiveStorageEncryption::UnknownCiphertextFormat, "Unknown encryption scheme version #{version.inspect}"
      end
      Object.const_get(scheme_class_name).new(encryption_key.b)
    end

    # Opens the object, reads the header which tells us how the ciphertext after it was written,
    # and yields an IO positioned at the start of that ciphertext together with the matching scheme.
    def open_ciphertext(key, encryption_key)
      ciphertext_io = SeekableObjectIO.new(object_for(key))
      header = ciphertext_io.read(CIPHERTEXT_HEADER_BYTE_SIZE)
      if header.nil? || header.byteslice(0, CIPHERTEXT_MAGIC_BYTES.bytesize) != CIPHERTEXT_MAGIC_BYTES
        raise ActiveStorageEncryption::UnknownCiphertextFormat,
          "Object #{key.inspect} in #{name} was not written by #{self.class.name} (no #{CIPHERTEXT_MAGIC_BYTES} header)"
      end

      scheme = scheme_for(header.getbyte(CIPHERTEXT_MAGIC_BYTES.bytesize), encryption_key)
      yield ciphertext_io.rebase(CIPHERTEXT_HEADER_BYTE_SIZE), scheme
    rescue Aws::S3::Errors::NoSuchKey
      raise ActiveStorage::FileNotFoundError
    end

    def stream(key, encryption_key, &blk)
      open_ciphertext(key, encryption_key) do |ciphertext_io, scheme|
        scheme.streaming_decrypt(from_ciphertext_io: ciphertext_io, &blk)
      end
    end

    # ActiveStorage passes exclusive ranges in some places (`0...4.kilobytes` when identifying a
    # blob) and inclusive ones in others, while the schemes only understand inclusive ranges.
    def inclusive(range)
      range.exclude_end? ? (range.begin..(range.end - 1)) : range
    end

    def ensure_integrity_of(key, checksum, plaintext_io)
      return if plaintext_io.base64digest == checksum

      delete key
      raise ActiveStorage::IntegrityError
    end

    def private_url(key, **options)
      # :require_headers is refused in the constructor, and :disable raises inside this call,
      # so streaming through a controller is all that is left.
      private_url_for_streaming_via_controller(key, **options)
    end

    def public_url(key, **)
      raise "This should never be called"
    end

    # Passes plaintext through to the cipher while digesting it, so that the checksum
    # ActiveStorage computed over the same bytes can be verified after the upload.
    class PlaintextChecksumIO
      def initialize(io)
        @io = io
        @digest = OpenSSL::Digest.new("MD5")
      end

      def read(n_bytes = nil, outbuf = nil)
        bytes_read = outbuf ? @io.read(n_bytes, outbuf) : @io.read(n_bytes)
        @digest << bytes_read if bytes_read
        bytes_read
      end

      def base64digest
        @digest.base64digest
      end
    end
  end
end
