# frozen_string_literal: true

require "test_helper"

# The in-memory tests in client_side_encrypted_s3_service_test.rb prove the logic of the service.
# These prove the integration: that a real bucket answers ranged GET requests the way this service
# needs it to, that multipart uploads of files larger than one part reassemble correctly, and that
# the round trip survives a real network. They are skipped unless credentials are in the ENV.
#
# Point them at an S3-compatible provider by setting S3_ENDPOINT as well - R2 for instance, which
# is worth testing separately from AWS because it is a different implementation of the same API:
#
#   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
#   S3_BUCKET=my-bucket S3_ENDPOINT=https://<account>.eu.r2.cloudflarestorage.com \
#   bin/rails test test/lib/client_side_encrypted_s3_service_against_bucket_test.rb
class ActiveStorageEncryption::ClientSideEncryptedS3ServiceAgainstBucketTest < ActiveSupport::TestCase
  setup do
    if ENV["AWS_ACCESS_KEY_ID"].blank? || ENV["AWS_SECRET_ACCESS_KEY"].blank? || ENV["S3_BUCKET"].blank?
      skip "Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and S3_BUCKET to test against a real bucket"
    end

    @service = ActiveStorageEncryption::ClientSideEncryptedS3Service.new(**config)
    @service.name = "client_side_encrypted_s3"
    @written_keys = []
  end

  teardown do
    @written_keys&.each { |key| @service.delete(key) }
  end

  def config
    {
      access_key_id: ENV.fetch("AWS_ACCESS_KEY_ID"),
      secret_access_key: ENV.fetch("AWS_SECRET_ACCESS_KEY"),
      region: ENV.fetch("S3_REGION", "auto"),
      bucket: ENV.fetch("S3_BUCKET")
    }.tap do |options|
      # R2 and other S3-compatible providers need the endpoint named, and path style addressing
      options.merge!(endpoint: ENV["S3_ENDPOINT"], force_path_style: true) if ENV["S3_ENDPOINT"].present?
    end
  end

  # The bucket is shared with other runs, so keys carry a per-run prefix
  def key_for(name)
    @run_id ||= SecureRandom.base36(10)
    "#{@run_id}-#{name}".tap { |key| @written_keys << key }
  end

  def test_round_trip_of_an_object_spanning_several_upload_parts
    key = key_for("large")
    encryption_key = Random.bytes(68)
    plaintext = Random.bytes(11.megabytes + 17) # More than two 5 MB parts

    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key, checksum: Digest::MD5.base64digest(plaintext))
    assert @service.exist?(key)

    readback = (+"").b
    @service.download(key, encryption_key: encryption_key) { |chunk| readback << chunk }
    assert_equal plaintext.bytesize, readback.bytesize
    assert_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(readback)
  end

  def test_ranged_reads_land_on_the_exact_plaintext_bytes
    key = key_for("ranges")
    encryption_key = Random.bytes(68)
    plaintext = Random.bytes(6.megabytes + 1023)
    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)

    last_offset = plaintext.bytesize - 1
    ranges = [
      0..0,                       # single byte at the start
      100..199,                   # inside the first read-ahead window
      0...4.kilobytes,            # exclusive, as blob identification asks for it
      (5.megabytes)..(5.megabytes + 511), # past a part boundary
      last_offset..last_offset    # single byte at the very end
    ]

    ranges.each do |range|
      assert_equal plaintext[range], @service.download_chunk(key, range, encryption_key: encryption_key), "range #{range} did not match"
    end
  end

  def test_the_bucket_holds_ciphertext_and_nothing_else
    key = key_for("ciphertext")
    encryption_key = Random.bytes(68)
    plaintext = "the deceased owned a house at 12 Example Street".b * 100
    @service.upload(key, StringIO.new(plaintext), encryption_key: encryption_key)

    # Read the object the way any holder of the bucket credentials would - without our key
    stored = @service.client.bucket(config.fetch(:bucket)).object(key).get.body.read.b
    refute_includes stored, "12 Example Street"
    assert_equal "ASEC", stored.byteslice(0, 4)

    assert_equal Digest::SHA256.hexdigest(plaintext), Digest::SHA256.hexdigest(@service.download(key, encryption_key: encryption_key))
  end

  def test_wrong_key_is_refused_and_missing_objects_are_reported
    key = key_for("wrong-key")
    encryption_key = Random.bytes(68)
    @service.upload(key, StringIO.new(Random.bytes(2048)), encryption_key: encryption_key)

    assert_raises(ActiveStorageEncryption::IncorrectEncryptionKey) do
      @service.download_chunk(key, 0..0, encryption_key: Random.bytes(68))
    end

    assert_raises(ActiveStorage::FileNotFoundError) do
      @service.download("#{key}-does-not-exist", encryption_key: encryption_key)
    end
  end

  def test_delete_removes_the_object
    key = key_for("deletable")
    @service.upload(key, StringIO.new(Random.bytes(1024)), encryption_key: Random.bytes(68))
    assert @service.exist?(key)

    @service.delete(key)
    refute @service.exist?(key)
  end
end
