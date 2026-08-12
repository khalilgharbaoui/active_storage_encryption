# frozen_string_literal: true

require "test_helper"
require_relative "../support/in_memory_s3"

class ActiveStorageEncryption::ClientSideEncryptedS3ServiceTest < ActiveSupport::TestCase
  setup do
    @service = ActiveStorageEncryption::ClientSideEncryptedS3Service.new(bucket: "test-bucket", region: "eu-central-1", stub_responses: true)
    @service.name = "client_side_encrypted_s3" # Needed for the controllers and service lookup
    @bucket = InMemoryS3.new(@service.client.client)

    ActiveStorage::Current.url_options = {host: "www.example.com", protocol: "https"}
  end

  def test_encrypted_question_method
    assert @service.encrypted?
  end

  def test_refuses_a_policy_which_would_hand_out_ciphertext
    error = assert_raises(ArgumentError) do
      ActiveStorageEncryption::ClientSideEncryptedS3Service.new(bucket: "test-bucket", region: "eu-central-1", stub_responses: true, private_url_policy: :require_headers)
    end
    assert_includes error.message, "require_headers"
  end

  def test_refuses_to_be_public
    assert_raises(ArgumentError) do
      ActiveStorageEncryption::ClientSideEncryptedS3Service.new(bucket: "test-bucket", region: "eu-central-1", stub_responses: true, public: true)
    end
  end

  def test_the_bucket_never_receives_the_plaintext
    key = "key-1"
    encryption_key = Random.bytes(68)
    plaintext = "the deceased owned a house at 12 Example Street" + generate_random_binary_string

    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)

    stored = @bucket.objects.fetch(key)
    refute_includes stored, "12 Example Street"
    refute_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(stored)
    assert_equal "ASEC", stored.byteslice(0, 4)
    assert_equal 2, stored.getbyte(4) # The scheme version, matching EncryptedDiskService's V2Scheme
  end

  def test_upload_then_download_using_the_correct_key
    key = "key-1"
    encryption_key = Random.bytes(68)
    plaintext = generate_random_binary_string

    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)
    assert @service.exist?(key)

    assert_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(@service.download(key, encryption_key: encryption_key))

    streamed = (+"").b
    @service.download(key, encryption_key: encryption_key) { |chunk| streamed << chunk }
    assert_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(streamed)
  end

  def test_upload_then_download_using_a_key_of_arbitrary_length
    key = "key-1"
    encryption_key = Random.new(Minitest.seed).bytes(128)
    plaintext = generate_random_binary_string

    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)
    assert_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(@service.download(key, encryption_key: encryption_key))
  end

  def test_upload_requires_a_key_of_sufficient_length
    assert_raises(ArgumentError) do
      @service.upload("key-1", StringIO.new(generate_random_binary_string), encryption_key: Random.bytes(12))
    end
  end

  def test_download_with_an_incorrect_key_refuses_before_reading_the_body
    key = "key-1"
    correct_key, incorrect_key = Random.new(Minitest.seed).bytes(68), Random.new(Minitest.seed + 1).bytes(68)
    plaintext = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext), encryption_key: correct_key)

    assert_raises(ActiveStorageEncryption::IncorrectEncryptionKey) do
      @service.download(key, encryption_key: incorrect_key) { |chunk| flunk "Plaintext escaped: #{chunk.bytesize} bytes" }
    end

    assert_raises(ActiveStorageEncryption::IncorrectEncryptionKey) do
      @service.download_chunk(key, 0..0, encryption_key: incorrect_key)
    end
  end

  def test_random_access_reads_the_requested_plaintext_range
    key = "key-1"
    encryption_key = Random.bytes(68)
    plaintext = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)

    inclusive_range = 1234..2345
    assert_equal plaintext[inclusive_range], @service.download_chunk(key, inclusive_range, encryption_key: encryption_key)

    # Ranges arrive exclusive too - ActiveStorage identifies a blob by reading `0...4.kilobytes`
    exclusive_range = 0...4.kilobytes
    assert_equal plaintext[exclusive_range], @service.download_chunk(key, exclusive_range, encryption_key: encryption_key)

    # And the single byte the proxy controller reads to check the key before it starts streaming
    assert_equal plaintext[0..0], @service.download_chunk(key, 0..0, encryption_key: encryption_key)

    last_byte_offset = plaintext.bytesize - 1
    assert_equal plaintext[last_byte_offset..], @service.download_chunk(key, last_byte_offset..last_byte_offset, encryption_key: encryption_key)
  end

  def test_upload_with_a_checksum_verifies_the_plaintext_and_removes_the_object_when_it_differs
    key = "key-1"
    encryption_key = Random.bytes(68)
    plaintext = generate_random_binary_string

    assert_raises(ActiveStorage::IntegrityError) do
      @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key, checksum: Digest::MD5.base64digest("something else entirely"))
    end
    refute @service.exist?(key)

    assert_nothing_raised do
      @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key, checksum: Digest::MD5.base64digest(plaintext))
    end
    assert @service.exist?(key)
  end

  def test_a_tampered_ciphertext_never_returns_plaintext_from_a_buffered_download
    key = "key-1"
    encryption_key = Random.bytes(68)
    plaintext = generate_random_binary_string
    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)

    flip_one_ciphertext_byte(key)

    assert_raises(OpenSSL::Cipher::CipherError) do
      @service.download(key, encryption_key: encryption_key)
    end
  end

  # The honest limitation of streaming AEAD, and the reason a framed scheme is worth having:
  # GCM can only verify its tag once the whole ciphertext has been read, so a download which
  # yields chunks has already handed some of them out by the time the tag fails. Callers who
  # need the guarantee must use the buffered form above.
  def test_a_tampered_ciphertext_raises_only_after_yielding_from_a_streaming_download
    key = "key-1"
    encryption_key = Random.bytes(68)
    @service.upload(key, StringIO.new(generate_random_binary_string), encryption_key: encryption_key)

    flip_one_ciphertext_byte(key)

    yielded_chunks = 0
    assert_raises(OpenSSL::Cipher::CipherError) do
      @service.download(key, encryption_key: encryption_key) { |_chunk| yielded_chunks += 1 }
    end
    assert yielded_chunks > 0, "expected the streaming download to have yielded before failing"
  end

  def test_composes_objects
    keys = ["key-1", "key-2"]
    encryption_keys = [Random.bytes(68), Random.bytes(68)]
    plaintexts = [generate_random_binary_string, generate_random_binary_string]

    keys.zip(encryption_keys, plaintexts).each do |(key, encryption_key, plaintext)|
      @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)
    end

    composed_key = "key-3"
    composed_encryption_key = Random.bytes(68)
    @service.compose(keys, composed_key, source_encryption_keys: encryption_keys, encryption_key: composed_encryption_key)

    readback = @service.download(composed_key, encryption_key: composed_encryption_key)
    assert_equal Digest::SHA256.hexdigest(plaintexts.join), Digest::SHA256.hexdigest(readback)
  end

  def test_compose_refuses_a_mismatched_number_of_keys
    assert_raises(ArgumentError) do
      @service.compose(["key-1", "key-2"], "key-3", source_encryption_keys: [Random.bytes(68)], encryption_key: Random.bytes(68))
    end
  end

  def test_delete
    key = "key-1"
    encryption_key = Random.bytes(68)
    @service.upload(key, StringIO.new(generate_random_binary_string), encryption_key: encryption_key)

    @service.delete(key)
    refute @service.exist?(key)
  end

  def test_downloading_a_missing_object
    assert_raises(ActiveStorage::FileNotFoundError) do
      @service.download("no-such-key", encryption_key: Random.bytes(68))
    end
    assert_raises(ActiveStorage::FileNotFoundError) do
      @service.download_chunk("no-such-key", 0..10, encryption_key: Random.bytes(68))
    end
  end

  def test_refuses_an_object_which_was_not_written_by_this_service
    @bucket.objects["plaintext-key"] = "this was put here by a stock S3 service"

    assert_raises(ActiveStorageEncryption::UnknownCiphertextFormat) do
      @service.download("plaintext-key", encryption_key: Random.bytes(68))
    end
  end

  def test_generates_a_streaming_url_and_refuses_one_when_disabled
    filename = ActiveStorage::Filename.new("temp.bin")

    @service.private_url_policy = :stream
    url = @service.url("key-1", blob_byte_size: 14, filename: filename, content_type: "binary/octet-stream", disposition: "inline", encryption_key: Random.bytes(32), expires_in: 10.seconds)
    assert_includes url, "/active-storage-encryption/blob/"

    @service.private_url_policy = :disable
    assert_raises(ActiveStorageEncryption::StreamingDisabled) do
      @service.url("key-1", blob_byte_size: 14, filename: filename, content_type: "binary/octet-stream", disposition: "inline", encryption_key: Random.bytes(32), expires_in: 10.seconds)
    end
  end

  def test_direct_uploads_are_routed_through_the_application
    key = "key-1"
    encryption_key = Random.bytes(68)
    plaintext = generate_random_binary_string
    checksum = Digest::MD5.base64digest(plaintext)

    # A browser has no key, so the PUT cannot go to the bucket - it goes to the controller in
    # this gem, which encrypts what it receives before it reaches the bucket.
    url = @service.url_for_direct_upload(key, expires_in: 60.seconds, content_type: "binary/octet-stream", content_length: plaintext.bytesize, checksum: checksum, encryption_key: encryption_key)
    assert_includes url, "/active-storage-encryption/blob/"

    headers = @service.headers_for_direct_upload(key, content_type: "binary/octet-stream", encryption_key: encryption_key, checksum: checksum)
    assert_equal Base64.strict_encode64(encryption_key), headers["x-active-storage-encryption-key"]
    assert_equal checksum, headers["content-md5"]

    previous_service = ActiveStorage::Blob.service
    ActiveStorage::Blob.service = @service # So that the controller can find it
    uri = URI.parse(url)
    rack_env = {
      "SCRIPT_NAME" => "",
      "PATH_INFO" => uri.path,
      "QUERY_STRING" => uri.query,
      "REQUEST_METHOD" => "PUT",
      "SERVER_NAME" => uri.host,
      "rack.input" => StringIO.new(plaintext),
      "CONTENT_LENGTH" => plaintext.bytesize.to_s(10),
      "CONTENT_TYPE" => "binary/octet-stream",
      "HTTP_X_ACTIVE_STORAGE_ENCRYPTION_KEY" => Base64.strict_encode64(encryption_key),
      "HTTP_CONTENT_MD5" => checksum,
      "action_dispatch.request.parameters" => {"token" => uri.path.split("/").last}
    }
    status, _headers, _body = ActiveStorageEncryption::EncryptedBlobsController.action(:update).call(rack_env)
    assert_equal 204, status

    assert_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(@service.download(key, encryption_key: encryption_key))
  ensure
    ActiveStorage::Blob.service = previous_service
  end

  def test_headers_for_private_download_carry_no_key
    assert_empty @service.headers_for_private_download("key-1", encryption_key: Random.bytes(68))
  end

  def test_service_name
    assert_equal "ClientSideEncryptedS3", @service.service_name
  end

  private

  def flip_one_ciphertext_byte(key)
    stored = @bucket.objects.fetch(key)
    offset = stored.bytesize / 2
    stored.setbyte(offset, stored.getbyte(offset) ^ 0xFF)
  end

  def generate_random_binary_string(size = 17.kilobytes + 13)
    Random.bytes(size)
  end
end
