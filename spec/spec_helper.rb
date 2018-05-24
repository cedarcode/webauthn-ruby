# frozen_string_literal: true

require "bundler/setup"
require "webauthn"
require "cbor"

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
    },
    security_key_direct: {
      credential_creation_options: {
        challenge: '11CzaFXezx7YszNaYE3pag=='
      },
      authenticator_attestation_response: {
        attestation_object: 'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgekOQZSd0/dNZZ3iBBaKWUVaYx49+w37LunPGKthcYG8CICFt3JdafYmqC3oAHDeFkLYM0eQjWPjZkh7WBqvRCcR9Y3g1Y4FZAsIwggK+MIIBpqADAgECAgR0hv3CMA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjBvMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMSgwJgYDVQQDDB9ZdWJpY28gVTJGIEVFIFNlcmlhbCAxOTU1MDAzODQyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAElV3zrfckfTF17/2cxPMaToeOuuGBCVZhUPs4iy5fZSe/V0CapYGlDQrFLxhEXAoTVIoTU8ik5ZpwTlI7wE3r7aNsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBSAwIQYLKwYBBAGC5RwBAQQEEgQQ+KAR84wKTRWABhcRH57cfTAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAxXEiA5ppSfjhmib1p/Qqob0nrnk6FRUFVb6rQCzoAih3cAflsdvZoNhqR4jLIEKecYwdMm256RusdtdhcREifhop2Q9IqXIYuwD8D5YSL44B9es1V+OGuHuITrHOrSyDj+9UmjLB7h4AnHR9L4OXdrHNNOliXvU1zun81fqIIyZ2KTSkC5gl6AFxNyQTcChgSDgr30Az8lpoohuWxsWHz7cvGd6Z41/tTA5zNoYa+NLpTMZUjQ51/2Upw8jBiG5PEzkJo0xdNlDvGrj/JN8LeQ9a0TiEVPfhQkl+VkGIuvEbg6xjGQfD+fm8qCamykHcZ9i5hNaGQMqITwJi3KDzuaGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj+SuuaKGMseZXPO6gx2XY0EAAAAAAAAAAAAAAAAAAAAAAAAAAABA2Nc6mqO+eIH0eIAhy1xfIJcjHtlOAsRLHxf4u5apXnhI6j8oGbmF87Qz6L8AvGjlHQLjGhAXjLpBFb2aeVowSqUBAgMmIAEhWCBsj3dTr9jqWWOwuDzWAQOqqugB1YGYKpE/YqHfRB3GrCJYIPiyHJ4rYZRaqfJQKAInKzINuxkQARzVdNcChyszi/Pr',
        client_data_json: 'eyJjaGFsbGVuZ2UiOiIxMUN6YUZYZXp4N1lzek5hWUUzcGFnIiwiY2xpZW50RXh0ZW5zaW9ucyI6e30sImhhc2hBbGdvcml0aG0iOiJTSEEtMjU2Iiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9'
      }
    }
  }
end

def hash_to_encoded_json(hash)
  Base64.urlsafe_encode64(hash.to_json)
end

def hash_to_encoded_cbor(hash)
  Base64.urlsafe_encode64(CBOR.encode(hash))
end
