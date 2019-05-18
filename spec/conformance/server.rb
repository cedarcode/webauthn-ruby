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

Credential = Struct.new(:id, :public_key) do
  @credentials = {}

  def self.register(username, id:, public_key:)
    @credentials[username] ||= []
    @credentials[username] << Credential.new(id, public_key)
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
end

post "/attestation/options" do
  options = base64_credential_creation_options
  options[:user][:name] = params["username"]
  options[:user][:displayName] = params["displayName"]
  options[:attestation] = params["attestation"]
  options[:authenticatorSelection] = params["authenticatorSelection"]
  options[:extensions] = params["extensions"]
  options[:excludeCredentials] = Credential.registered_for(params["username"]).map(&:descriptor)

  cookies["username"] = params["username"]
  cookies["challenge"] = options[:challenge]

  render_ok(options)
end

post "/attestation/result" do
  attestation_object = Base64.urlsafe_decode64(params["response"]["attestationObject"])
  client_data_json = Base64.urlsafe_decode64(params["response"]["clientDataJSON"])
  attestation_response = WebAuthn::AuthenticatorAttestationResponse.new(
    attestation_object: attestation_object,
    client_data_json: client_data_json
  )

  public_key_credential = WebAuthn::PublicKeyCredential.new(
    type: params["type"],
    id: params["id"],
    raw_id: Base64.urlsafe_decode64(params["rawId"]),
    response: attestation_response
  )

  expected_challenge = Base64.urlsafe_decode64(cookies["challenge"])
  public_key_credential.verify(expected_challenge)

  Credential.register(
    cookies["username"],
    id: Base64.urlsafe_encode64(attestation_response.credential.id, padding: false),
    public_key: attestation_response.credential.public_key
  )

  cookies["challenge"] = nil
  cookies["username"] = nil

  render_ok
end

post "/assertion/options" do
  options = base64_credential_request_options
  options[:allowCredentials] = Credential.registered_for(params["username"]).map(&:descriptor)
  options[:extensions] = params["extensions"]
  options[:userVerification] = params["userVerification"]

  cookies["username"] = params["username"]
  cookies["challenge"] = options[:challenge]

  render_ok(options)
end

post "/assertion/result" do
  credential_id = Base64.urlsafe_decode64(params["id"])
  authenticator_data = Base64.urlsafe_decode64(params["response"]["authenticatorData"])
  client_data_json = Base64.urlsafe_decode64(params["response"]["clientDataJSON"])
  signature = Base64.urlsafe_decode64(params["response"]["signature"])

  assertion_response = WebAuthn::AuthenticatorAssertionResponse.new(
    credential_id: credential_id,
    authenticator_data: authenticator_data,
    client_data_json: client_data_json,
    signature: signature
  )

  public_key_credential = WebAuthn::PublicKeyCredential.new(
    type: params["type"],
    id: params["id"],
    raw_id: Base64.urlsafe_decode64(params["rawId"]),
    response: assertion_response
  )

  expected_challenge = Base64.urlsafe_decode64(cookies["challenge"])

  allowed_credentials = Credential.registered_for(cookies["username"]).map do |c|
    { id: Base64.urlsafe_decode64(c.id), public_key: c.public_key }
  end

  public_key_credential.verify(expected_challenge, allowed_credentials: allowed_credentials)

  cookies["challenge"] = nil
  cookies["username"] = nil

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

def base64_credential_creation_options
  options = WebAuthn.credential_creation_options
  options[:challenge] = Base64.urlsafe_encode64(options[:challenge], padding: false)
  options
end

def base64_credential_request_options
  options = WebAuthn.credential_request_options
  options[:challenge] = Base64.urlsafe_encode64(options[:challenge], padding: false)
  options
end
