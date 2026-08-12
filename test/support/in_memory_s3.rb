# frozen_string_literal: true

# A small in-memory stand-in for an S3 bucket, installed into an Aws::S3::Client through the
# SDK's own response stubbing. It exists so that the client-side encrypting service can be tested
# everywhere, rather than only on a machine holding credentials for a real bucket: encryption,
# ranged decryption and tamper detection are properties of our code, not of the storage provider.
#
# It implements only what the service asks of a bucket, and it implements ranged GET requests
# faithfully, because that is the part the service leans on hardest. Tests against a real bucket
# still exist alongside it - this double proves the logic, they prove the integration.
class InMemoryS3
  attr_reader :objects

  def initialize(client)
    @objects = {}
    @parts_per_upload = {}
    @n_uploads = 0
    install_into(client)
  end

  private

  def install_into(client)
    client.stub_responses(:put_object, ->(context) {
      @objects[context.params[:key]] = read_body(context.params[:body])
      {}
    })

    client.stub_responses(:create_multipart_upload, ->(_context) {
      upload_id = "upload-#{@n_uploads += 1}"
      @parts_per_upload[upload_id] = {}
      {upload_id: upload_id}
    })

    client.stub_responses(:upload_part, ->(context) {
      params = context.params
      @parts_per_upload.fetch(params[:upload_id])[params[:part_number]] = read_body(params[:body])
      {etag: "\"part-#{params[:part_number]}\""}
    })

    client.stub_responses(:complete_multipart_upload, ->(context) {
      params = context.params
      parts = @parts_per_upload.delete(params[:upload_id]) || {}
      @objects[params[:key]] = parts.keys.sort.map { |part_number| parts[part_number] }.join.b
      {}
    })

    client.stub_responses(:abort_multipart_upload, ->(context) {
      @parts_per_upload.delete(context.params[:upload_id])
      {}
    })

    client.stub_responses(:head_object, ->(context) {
      bytes = @objects[context.params[:key]]
      # A raw 404, rather than an error class: Aws::S3::Object#exists? runs a waiter which
      # decides on the HTTP status, and only a real 404 means "no such object" to it.
      next {status_code: 404, headers: {}, body: ""} unless bytes

      {content_length: bytes.bytesize}
    })

    client.stub_responses(:delete_object, ->(context) {
      @objects.delete(context.params[:key])
      {}
    })

    client.stub_responses(:get_object, ->(context) {
      params = context.params
      bytes = @objects[params[:key]]
      next no_such_key_response unless bytes
      next {body: bytes, content_length: bytes.bytesize} unless params[:range]

      first, last = params[:range].match(/\Abytes=(\d+)-(\d+)\z/).captures.map(&:to_i)
      next Aws::S3::Errors::InvalidRange.new(nil, "Range Not Satisfiable") if first >= bytes.bytesize

      last = [last, bytes.bytesize - 1].min
      {
        body: bytes.byteslice(first, last - first + 1),
        content_length: last - first + 1,
        content_range: "bytes #{first}-#{last}/#{bytes.bytesize}"
      }
    })
  end

  def read_body(body)
    body.is_a?(String) ? body.b : body.read.b
  end

  # S3 tells a missing key apart from other 404s through the error code in the response body,
  # and the SDK turns that code into Aws::S3::Errors::NoSuchKey - which is what the service
  # translates into ActiveStorage::FileNotFoundError.
  def no_such_key_response
    {
      status_code: 404,
      headers: {},
      body: "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>"
    }
  end
end
