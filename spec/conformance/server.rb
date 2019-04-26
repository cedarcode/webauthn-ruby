# frozen_string_literal: true

require "webauthn"
require "sinatra"
require "rack/contrib"
require "sinatra/cookies"
require "byebug"

use Rack::PostBodyContentTypeParser
set show_exceptions: false

RP_NAME = "webauthn-ruby #{WebAuthn::VERSION} conformance test server"

ClientRequest =
  Struct.new(:user_name, :display_name, :attestation, :authenticator_selection, :extensions, :credentials) do
    @storage = {}

    def self.find(user_name)
      @storage.fetch(user_name)
    end

    def self.find_or_create(params)
      @storage[params["username"]] ||= ClientRequest.new(
        params["username"],
        params["displayName"],
        params["attestation"],
        params["authenticatorSelection"],
        params["extensions"] || { "example.extension": true },
        []
      )
    end

    def public_key_credential_descriptors
      credentials.map { |credential| { id: credential[:credential_id], type: "public-key" } }
    end
  end

post "/attestation/options" do
  req = ClientRequest.find_or_create(params)
  cookies["username"] = req.user_name

  options = base64_credential_creation_options
  options[:user][:name] = req.user_name
  options[:user][:displayName] = req.display_name
  options[:attestation] = req.attestation
  options[:authenticatorSelection] = req.authenticator_selection
  options[:extensions] = req.extensions
  options[:excludeCredentials] = req.public_key_credential_descriptors

  cookies["challenge"] = options[:challenge]
  render_ok(options)
end

post "/attestation/result" do
  attestation_response = WebAuthn::Attestation.from_json(params)

  expected_challenge = Base64.urlsafe_decode64(cookies["challenge"])
  expected_origin = "http://localhost:#{settings.port}"
  attestation_response.verify(expected_challenge, expected_origin)

  req = ClientRequest.find(cookies["username"])
  req.credentials << {
    credential_id: Base64.urlsafe_encode64(attestation_response.credential.id, padding: false),
    public_key: attestation_response.credential.public_key,
  }

  render_ok
end

post "/assertion/options" do
  req = ClientRequest.find(cookies["username"])
  options = base64_credential_request_options
  options[:allowCredentials] = req.public_key_credential_descriptors
  options[:extensions] = req.extensions
  options[:userVerification] = params["userVerification"]

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

  expected_challenge = Base64.urlsafe_decode64(cookies["challenge"])
  expected_origin = "http://localhost:#{settings.port}"
  allowed_credentials = ClientRequest.find(cookies["username"]).credentials
  assertion_response.verify(expected_challenge, expected_origin, allowed_credentials: allowed_credentials)

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
  options[:rp][:name] = RP_NAME
  options[:challenge] = Base64.urlsafe_encode64(options[:challenge], padding: false)
  options
end

def base64_credential_request_options
  options = WebAuthn.credential_request_options
  options[:challenge] = Base64.urlsafe_encode64(options[:challenge], padding: false)
  options
end
