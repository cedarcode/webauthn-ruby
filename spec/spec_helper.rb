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

class FakeAuthenticator
  def initialize(challenge: fake_challenge, origin: fake_origin, mode: :get)
    @challenge = challenge
    @mode = mode
    @origin = origin
  end

  def authenticator_data(rp_id: nil, user_present: true)
    @authenticator_data ||=
      begin
        rp_id ||= "localhost"
        rp_id_hash = OpenSSL::Digest::SHA256.digest(rp_id)

        if user_present
          user_present_bit = "1"
        else
          user_present_bit = "0"
        end

        attested_credential_data_present_bit = "0"

        raw_flags = ["#{user_present_bit}00000#{attested_credential_data_present_bit}0"].pack("b*")
        raw_sign_count = "0000"

        rp_id_hash + raw_flags + raw_sign_count
      end
  end

  def client_data_json
    @client_data_json ||= { challenge: encode(challenge), origin: origin, type: type }.to_json
  end

  def credential_key
    @credential_key ||= OpenSSL::PKey::EC.new("prime256v1").generate_key
  end

  def signature
    @signature ||= credential_key.sign("SHA256", authenticator_data + OpenSSL::Digest::SHA256.digest(client_data_json))
  end

  private

  attr_reader :challenge, :mode, :origin

  def type
    "webauthn.#{mode}"
  end

  def encode(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end
end

def fake_authenticator_data(rp_id: nil, user_present: true, credential_public_key: nil)
  rp_id ||= "localhost"
  rp_id_hash = OpenSSL::Digest::SHA256.digest(rp_id)

  if user_present
    user_present_bit = "1"
  else
    user_present_bit = "0"
  end

  attested_credential_data_present_bit = "1"

  raw_flags = ["#{user_present_bit}00000#{attested_credential_data_present_bit}0"].pack("b*")
  raw_sign_count = "0000"

  rp_id_hash + raw_flags + raw_sign_count + fake_attested_credential_data(public_key: credential_public_key)
end

def fake_attested_credential_data(public_key: nil)
  aaguid = SecureRandom.random_bytes(16)
  id = SecureRandom.random_bytes(16)
  public_key ||= fake_credential_key.public_key
  public_key_bytes = key_bytes(public_key)

  public_key = CBOR.encode(
    -2 => public_key_bytes[1..32],
    -3 => public_key_bytes[33..64]
  )

  aaguid + [id.length].pack("n*") + id + public_key
end

def fake_attestation_object
  CBOR.encode(
    "fmt" => "none",
    "attStmt" => {},
    "authData" => fake_authenticator_data
  )
end

def encoded_fake_attestation_object(*args)
  WebAuthn::Utils.ua_encode(fake_attestation_object(*args))
end

def fake_origin
  "http://localhost"
end

def fake_challenge
  SecureRandom.random_bytes(16)
end

def fake_client_data_json(challenge: nil, origin: nil, type: nil)
  {
    challenge: authenticator_encode(challenge || fake_challenge),
    origin: origin || fake_origin,
    type: type || "webauthn.create"
  }.to_json
end

def encoded_fake_client_data_json(*args)
  WebAuthn::Utils.ua_encode(fake_client_data_json(*args))
end

def fake_credential_key
  OpenSSL::PKey::EC.new("prime256v1").generate_key
end

def key_bytes(public_key)
  public_key.to_bn.to_s(2)
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
  WebAuthn::Utils.ua_encode(hash.to_json)
end

def hash_to_encoded_cbor(hash)
  WebAuthn::Utils.ua_encode(CBOR.encode(hash))
end

def authenticator_encode(bin)
  Base64.urlsafe_encode64(bin, padding: false)
end
