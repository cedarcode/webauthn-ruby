# frozen_string_literal: true

require "bundler/setup"
require "webauthn"

require "byebug"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def seeds
  {
    yubikey_4: {
      credential_creation_options: {
        challenge: 'SJoqxXSZAlElBfSa11DtZQ=='
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQPx8VO/e2RN8kYB4fx1r1JqiqxukuoebUJrb5LDjVhNX5qefpOiOsQ/GWvQDVnzF4AugvPs/WCUZ+tOp6hpmZp6lAQIDJiABIVggblr3cP0yKHKavNkN4R7AecQKZsRZriWO79Kgwzvon8MiWCBdEB+QtzhJj+HkkvQPbVxK+HUDNtkIIBmhqGquQrn6YQ==',
        client_data_json: 'eyJjaGFsbGVuZ2UiOiJTSm9xeFhTWkFsRWxCZlNhMTFEdFpRIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
      }
    },
    security_key: {
      credential_creation_options: {
        challenge: 'Aag9PJLQvC2ixwZCHzs2Yw=='
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4/krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQN+zoWcbFDyyOvchxWedAB6FwzMqB0Fmmr+VnWlMzR9lqhoPSb/1388CluAR/JDTSykFMwzxT+EASYD5w/djXNulAQIDJiABIVggxTGmnso/zNWSp7ZSOm7hQqfUtJZylvCj+7fYoi7UG54iWCCJi3gYqD9rYJEfiAlRKYVGqqtp1mmur1OCS2Tgno7Qxg==',
        client_data_json: 'eyJjaGFsbGVuZ2UiOiJBYWc5UEpMUXZDMml4d1pDSHpzMll3IiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
      }
    }
  }
end
