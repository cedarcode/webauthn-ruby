# frozen_string_literal: true

require "base64"
require "json"
require "webauthn"
require "sinatra"
require "rack/contrib"
require "sinatra/cookies"
require "byebug"

use Rack::PostBodyContentTypeParser
set show_exceptions: false

RP_NAME = "webauthn-ruby #{WebAuthn::VERSION} conformance test server"

Credential = Struct.new(:id, :public_key, :sign_count) do
  @credentials = {}

  def self.register(username, id:, public_key:, sign_count:)
    @credentials[username] ||= []
    @credentials[username] << Credential.new(id, public_key, sign_count)
  end

  def self.registered_for(username)
    @credentials[username] || []
  end

  def descriptor
    { type: "public-key", id: id }
  end
end

host = ENV["HOST"] || "localhost"

WebAuthn.configure do |config|
  config.origin = "http://#{host}:#{settings.port}"
  config.rp_name = RP_NAME
  config.algorithms.concat(%w(ES384 ES512 PS384 PS512 RS384 RS512 RS1))
end

post "/attestation/options" do
  options = WebAuthn::CredentialCreationOptions.new(
    attestation: params["attestation"],
    authenticator_selection: params["authenticatorSelection"],
    exclude_credentials: Credential.registered_for(params["username"]).map(&:descriptor),
    extensions: params["extensions"],
    user_id: "1",
    user_name: params["username"],
    user_display_name: params["displayName"]
  ).to_h

  options[:challenge] = Base64.urlsafe_encode64(options[:challenge], padding: false)

  cookies["username"] = params["username"]
  cookies["challenge"] = options[:challenge]

  render_ok(options)
end

post "/attestation/result" do
  public_key_credential = WebAuthn::PublicKeyCredential.from_create(params, encoding: :base64url)
  expected_challenge = Base64.urlsafe_decode64(cookies["challenge"])
  public_key_credential.verify(expected_challenge)

  Credential.register(
    cookies["username"],
    id: Base64.urlsafe_encode64(public_key_credential.response.credential.id, padding: false),
    public_key: public_key_credential.response.credential.public_key,
    sign_count: public_key_credential.response.authenticator_data.sign_count,
  )

  cookies["challenge"] = nil
  cookies["username"] = nil

  render_ok
end

post "/assertion/options" do
  options = WebAuthn::CredentialRequestOptions.new(
    allow_credentials: Credential.registered_for(params["username"]).map(&:descriptor),
    extensions: params["extensions"],
    user_verification: params["userVerification"]
  ).to_h

  options[:challenge] = Base64.urlsafe_encode64(options[:challenge], padding: false)

  cookies["username"] = params["username"]
  cookies["userVerification"] = params["userVerification"]
  cookies["challenge"] = options[:challenge]

  render_ok(options)
end

post "/assertion/result" do
  public_key_credential = WebAuthn::PublicKeyCredential.from_get(params, encoding: :base64url)
  expected_challenge = Base64.urlsafe_decode64(cookies["challenge"])

  allowed_credentials = Credential.registered_for(cookies["username"]).map do |c|
    { id: Base64.urlsafe_decode64(c.id), public_key: c.public_key, sign_count: c.sign_count }
  end

  public_key_credential.verify(
    expected_challenge,
    allowed_credentials: allowed_credentials,
    user_verification: cookies["userVerification"] == "required"
  )

  used_credential = Credential.registered_for(cookies["username"]).detect do |c|
    c.id == public_key_credential.id
  end
  used_credential.sign_count = public_key_credential.response.authenticator_data.sign_count
  cookies["challenge"] = nil
  cookies["username"] = nil
  cookies["userVerification"] = nil

  render_ok
end

error 500 do
  error = env["sinatra.error"]
  render_error(<<~MSG)
    #{error.class}: #{error.message}
    #{error.backtrace.take(10).join("\n")}
  MSG
end

private

def render_ok(params = {})
  JSON.dump({ status: "ok", errorMessage: "" }.merge!(params))
end

def render_error(message)
  JSON.dump(status: "error", errorMessage: message)
end
