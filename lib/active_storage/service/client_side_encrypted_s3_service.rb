# frozen_string_literal: true

# Needed so that Rails can find our service definition. It will perform the following
# steps. Given a "ClientSideEncryptedS3" value of the `service:` key in the YAML, it will:
#
# * Force-require a file at "active_storage/service/client_side_encrypted_s3", from any path on the $LOAD_PATH
# * Instantiate a class called "ActiveStorage::Service::ClientSideEncryptedS3Service"
require_relative "../../active_storage_encryption"
class ActiveStorage::Service::ClientSideEncryptedS3Service < ActiveStorageEncryption::ClientSideEncryptedS3Service
end
