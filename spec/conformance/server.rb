# frozen_string_literal: true

require "json"
require "webauthn"
require "sinatra"
require "rack/contrib"
require "sinatra/cookies"
require "byebug"

require_relative "conformance_cache_store"
require_relative "conformance_patches"

use Rack::PostBodyContentTypeParser
set show_exceptions: false

# TODO: remove once safetynet attestation P-1 test certificate problem is fixed
# https://github.com/fido-alliance/conformance-tools-issues/issues/518
require 'android_safetynet/attestation_response'
AndroidSafetynet::AttestationResponse.trust_store = nil

RP_NAME = "webauthn-ruby #{WebAuthn::VERSION} conformance test server"
UNACCEPTABLE_STATUSES = ["USER_VERIFICATION_BYPASS", "ATTESTATION_KEY_COMPROMISE", "USER_KEY_REMOTE_COMPROMISE",
                         "USER_KEY_PHYSICAL_COMPROMISE", "REVOKED"].freeze

Credential = Struct.new(:id, :public_key, :sign_count) do
  @credentials = {}

  def self.register(username, id:, public_key:, sign_count:)
    @credentials[username] ||= []
    @credentials[username] << Credential.new(id, public_key, sign_count)
  end

  def self.registered_for(username)
    @credentials[username] || []
  end
end

host = ENV["HOST"] || "localhost"

WebAuthn.configure do |config|
  config.origin = "http://#{host}:#{settings.port}"
  config.rp_name = RP_NAME
  config.algorithms.concat(%w(ES384 ES512 PS384 PS512 RS384 RS512 RS1))
  config.silent_authentication = true
  config.fido_metadata_token = ""
  config.fido_metadata_cache_backend = ConformanceCacheStore.new
  config.fido_metadata_cache_backend.setup_authenticators
  config.fido_metadata_cache_backend.setup_metadata_store
end

post "/attestation/options" do
  options = WebAuthn::Credential.options_for_create(
    attestation: params["attestation"],
    authenticator_selection: params["authenticatorSelection"],
    exclude: Credential.registered_for(params["username"]).map(&:id),
    extensions: params["extensions"],
    user: { id: "1", name: params["username"], display_name: params["displayName"] }
  )

  cookies["attestation_username"] = params["username"]
  cookies["attestation_challenge"] = options.challenge

  if params["authenticatorSelection"] && params["authenticatorSelection"]["userVerification"]
    cookies["attestation_user_verification"] = params["authenticatorSelection"]["userVerification"]
  end

  render_ok(options.as_json)
end

post "/attestation/result" do
  webauthn_credential = WebAuthn::Credential.from_create(params)

  webauthn_credential.verify(
    cookies["attestation_challenge"],
    user_verification: cookies["attestation_user_verification"] == "required"
  )

  metadata_entry = webauthn_credential.response.attestation_statement.fido_metadata_entry
  verify_authenticator_status(metadata_entry)

  Credential.register(
    cookies["attestation_username"],
    id: webauthn_credential.id,
    public_key: webauthn_credential.public_key,
    sign_count: webauthn_credential.sign_count,
  )

  cookies["attestation_challenge"] = nil
  cookies["attestation_username"] = nil
  cookies["attestation_user_verification"] = nil

  render_ok
end

post "/assertion/options" do
  options = WebAuthn::Credential.options_for_get(
    allow: Credential.registered_for(params["username"]).map(&:id),
    extensions: params["extensions"],
    user_verification: params["userVerification"]
  )

  cookies["assertion_username"] = params["username"]
  cookies["assertion_user_verification"] = params["userVerification"]
  cookies["assertion_challenge"] = options.challenge

  render_ok(options.as_json)
end

post "/assertion/result" do
  webauthn_credential = WebAuthn::Credential.from_get(params)

  user_credential = Credential.registered_for(cookies["assertion_username"]).detect do |uc|
    uc.id == webauthn_credential.id
  end

  webauthn_credential.verify(
    cookies["assertion_challenge"],
    public_key: user_credential.public_key,
    sign_count: user_credential.sign_count,
    user_verification: cookies["assertion_user_verification"] == "required"
  )

  user_credential.sign_count = webauthn_credential.sign_count
  cookies["assertion_challenge"] = nil
  cookies["assertion_username"] = nil
  cookies["assertion_user_verification"] = nil

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

def verify_authenticator_status(entry)
  return unless entry

  raise("bad authenticator status") if entry.status_reports.any? do |status_report|
    UNACCEPTABLE_STATUSES.include?(status_report.status)
  end
end
