# frozen_string_literal: true

require "bundler/setup"
require "webauthn"
require "libcbor/all"

require "byebug"
require "webauthn/fake_authenticator"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def fake_origin
  "http://localhost"
end

def fake_challenge
  SecureRandom.random_bytes(32)
end

def fake_cose_credential_key(algorithm: nil, x_coordinate: nil, y_coordinate: nil)
  kty_label = 1
  alg_label = 3
  crv_label = -1
  x_label = -2
  y_label = -3

  kty_ec2 = 2
  alg_es256 = -7
  crv_p256 = 1

  CBOR.encode(
    kty_label => kty_ec2,
    alg_label => algorithm || alg_es256,
    crv_label => crv_p256,
    x_label => x_coordinate || SecureRandom.random_bytes(32),
    y_label => y_coordinate || SecureRandom.random_bytes(32)
  )
end

def key_bytes(public_key)
  public_key.to_bn.to_s(2)
end
