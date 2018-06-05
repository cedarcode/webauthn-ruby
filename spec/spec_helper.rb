# frozen_string_literal: true

require "bundler/setup"
require "webauthn"
require "cbor"

require "byebug"
require "support/fake_authenticator"

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
  SecureRandom.random_bytes(16)
end

def key_bytes(public_key)
  public_key.to_bn.to_s(2)
end
