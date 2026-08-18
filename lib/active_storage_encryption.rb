# frozen_string_literal: true

require "active_storage_encryption/version"
require "active_storage_encryption/engine"

module ActiveStorageEncryption
  autoload :PrivateUrlPolicy, __dir__ + "/active_storage_encryption/private_url_policy.rb"
  autoload :EncryptedBlobsController, __dir__ + "/active_storage_encryption/encrypted_blobs_controller.rb"
  autoload :EncryptedBlobProxyController, __dir__ + "/active_storage_encryption/encrypted_blob_proxy_controller.rb"
  autoload :EncryptedDiskService, __dir__ + "/active_storage_encryption/encrypted_disk_service.rb"
  autoload :EncryptedMirrorService, __dir__ + "/active_storage_encryption/encrypted_mirror_service.rb"
  autoload :EncryptedS3Service, __dir__ + "/active_storage_encryption/encrypted_s3_service.rb"
  autoload :ClientSideEncryptedS3Service, __dir__ + "/active_storage_encryption/client_side_encrypted_s3_service.rb"
  autoload :EncryptedGCSService, __dir__ + "/active_storage_encryption/encrypted_gcs_service.rb"
  autoload :Overrides, __dir__ + "/active_storage_encryption/overrides.rb"

  # Key provider for the `encryption_key` column on ActiveStorage::Blob - the key
  # that opens the file, kept encrypted in the database. Defaults to nil, meaning
  # ActiveRecord::Encryption's own key provider, which is what every app got
  # before this hook existed.
  #
  # Set it when the blob key should be sealed with something narrower than the
  # application-wide key - a per-user key, for instance, so that destroying that
  # one key makes that user's files unrecoverable, including from backups:
  #
  #   ActiveStorageEncryption.blob_key_provider = MyPerUserKeyProvider.new
  #
  # Assign it from an initializer. It is resolved on use rather than captured at
  # declaration, so load order does not matter, and re-declaring
  # `encrypts :encryption_key` in the host app would not work anyway: `encrypts`
  # decorates, so a second declaration encrypts the value twice.
  mattr_accessor :blob_key_provider

  # Defers to ActiveStorageEncryption.blob_key_provider at the moment a key is
  # actually needed. ActiveRecord::Encryption only duck-types this pair.
  class DeferredBlobKeyProvider
    def encryption_key
      resolve.encryption_key
    end

    def decryption_keys(encrypted_message)
      resolve.decryption_keys(encrypted_message)
    end

    private

    def resolve
      ActiveStorageEncryption.blob_key_provider || ActiveRecord::Encryption.key_provider
    end
  end

  class IncorrectEncryptionKey < ArgumentError
  end

  class StreamingDisabled < ArgumentError
  end

  # Raised when an object in a bucket does not carry the header a client-side encrypting
  # service writes ahead of its ciphertext - it was written by another service, or is not
  # encrypted at all.
  class UnknownCiphertextFormat < StandardError
  end

  class StreamingTokenInvalidOrExpired < ActiveSupport::MessageEncryptor::InvalidMessage
  end

  # Unlike MessageVerifier#verify, MessageEncryptor#decrypt_and_verify does not raise an exception if
  # the message decrypts, but has expired or was signed for a different purpose. We want an exception
  # to remove the annoying nil checks.
  class TokenEncryptor < ActiveSupport::MessageEncryptor
    def decrypt_and_verify(value, **options)
      super.tap do |message_or_nil|
        raise StreamingTokenInvalidOrExpired if message_or_nil.nil?
      end
    end
  end

  # Returns the ActiveSupport::MessageEncryptor which is used for encrypting the
  # streaming download URLs. These URLs need to contain the encryption key which
  # we do not want to reveal to the consumer. Note that this encryptor _is not_
  # used to encrypt the file data itself - ActiveSupport::MessageEncryptor is not
  # fit for streaming and not designed for file encryption use cases. We just use
  # this encryptor to encrypt the tokens in URLs (which is something the MessageEncryptor)
  # is actually good at.
  #
  # The encryptor gets configured using a key derived from the Rails secrets, in a similar
  # manner to the MessageVerifier provided for your Rails app by the Rails bootstrapping code.
  #
  # @return [ActiveSupport::MessageEncryptor] the configured encryptor.
  def self.token_encryptor
    # Rails has a per-app message verifier, which is used for different purposes:
    #
    # Rails.application.message_verifier('sensitive_data')
    #
    # The ActiveStorage verifier (`ActiveStorage.verifier`) is actually just:
    #
    # Rails.application.message_verifier('ActiveStorage')
    #
    # Sadly, unlike the verifier, a Rails app does not have a similar centrally
    # set-up `message_encryptor`, specifying a sane configuration (secret, encryption
    # scheme et cetera).
    #
    # The initialization code for the Rails-wide verifiers (it is plural since Rails initializes
    # verifiers according to the argument you pass to `message_verifier(purpose_or_name_of_using_module)`:
    #   ActiveSupport::MessageVerifiers.new do |salt, secret_key_base: self.secret_key_base|
    #     key_generator(secret_key_base).generate_key(salt)
    #   end.rotate_defaults
    #
    # The same API is actually supported by ActiveSupport::MessageEncryptors, see
    # https://api.rubyonrails.org/classes/ActiveSupport/MessageEncryptors.html
    # but we do not need multiple encryptors - one will do :-)
    secret_key_base = Rails.application.secret_key_base
    raise ArgumentError, "secret_key_base must be present on Rails.application" unless secret_key_base

    len = TokenEncryptor.key_len
    salt = Digest::SHA2.digest("ActiveStorageEncryption")
    raise "Salt must be the same length as the key" unless salt.bytesize == len
    key = ActiveSupport::KeyGenerator.new(secret_key_base).generate_key(salt, len)

    # We need an URL-safe serializer, since the tokens are used in a path in URLs
    TokenEncryptor.new(key, url_safe: true)
  end
end
