# frozen_string_literal: true

require "bundler/setup"
require "webauthn"
require "cbor"

require "byebug"
require "webauthn/fake_client"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.after do
    WebAuthn.instance_variable_set(:@configuration, nil)
  end
end

def create_credential(client: WebAuthn::FakeClient.new, rp_id: nil)
  rp_id ||= URI.parse(client.origin).host

  create_result = client.create(rp_id: rp_id)

  credential_public_key =
    WebAuthn::AuthenticatorAttestationResponse
    .new(
      attestation_object: create_result["response"]["attestationObject"],
      client_data_json: create_result["response"]["clientDataJSON"]
    )
    .credential
    .public_key

  [create_result["id"], credential_public_key]
end

def fake_origin
  "http://localhost"
end

def fake_challenge
  SecureRandom.random_bytes(32)
end

def fake_cose_credential_key(algorithm: -7, x_coordinate: nil, y_coordinate: nil)
  crv_p256 = 1

  COSE::Key::EC2.new(
    alg: algorithm,
    crv: crv_p256,
    x: x_coordinate || SecureRandom.random_bytes(32),
    y: y_coordinate || SecureRandom.random_bytes(32)
  ).serialize
end

def key_bytes(public_key)
  public_key.to_bn.to_s(2)
end

# Uses https://github.com/wolfcw/libfaketime/ to stub time. Unlike the Timecop gem this also works for C-extensions
# such as OpenSSL. The library must be loaded per the libfaketime's README for the relevant operating system, and use
# the DONT_FAKE_MONOTONIC=1 and FAKETIME_NO_CACHE=1 environment variables to work as expected for the test suite.
def fake_time(time)
  old_time = ENV["FAKETIME"]
  new_time = time.strftime("%Y-%m-%d %H:%M:%S")

  begin
    ENV["FAKETIME"] = new_time
    current = Time.now.strftime("%Y-%m-%d %H:%M:%S")
    skip("libfaketime not preloaded? current time is #{current} expected #{new_time}") if current != new_time

    yield
  ensure
    ENV["FAKETIME"] = old_time
  end
end

# Borrowed from activesupport
def silence_warnings
  old_verbose, $VERBOSE = $VERBOSE, nil
  yield
ensure
  $VERBOSE = old_verbose
end
