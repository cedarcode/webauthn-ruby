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
  def initialize(creation_options: nil, request_options: nil, context: {})
    @creation_options = creation_options
    @request_options = request_options
    @context = context
  end

  def authenticator_data
    @authenticator_data ||= rp_id_hash + raw_flags + raw_sign_count + attested_credential_data
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

  def attestation_object
    if create?
      CBOR.encode(
        "fmt" => "none",
        "attStmt" => {},
        "authData" => authenticator_data
      )
    end
  end

  private

  attr_reader :creation_options, :context, :request_options

  def rp_id_hash
    OpenSSL::Digest::SHA256.digest(rp_id)
  end

  def raw_flags
    ["#{user_present_bit}00000#{attested_credential_data_present_bit}0"].pack("b*")
  end

  def attested_credential_data_present_bit
    if attested_credential_data.length > 0
      "1"
    else
      "0"
    end
  end

  def attested_credential_data
    if create?
      aaguid + [credential_id.length].pack("n*") + credential_id + cose_credential_public_key
    else
      ""
    end
  end

  def cose_credential_public_key
    CBOR.encode(
      -2 => key_bytes(credential_key.public_key)[1..32],
      -3 => key_bytes(credential_key.public_key)[33..64]
    )
  end

  def credential_id
    @credential_id ||= SecureRandom.random_bytes(16)
  end

  def aaguid
    @aaguid ||= SecureRandom.random_bytes(16)
  end

  def raw_sign_count
    "0000"
  end

  def user_present_bit
    if user_present?
      "1"
    else
      "0"
    end
  end

  def type
    if create?
      "webauthn.create"
    elsif get?
      "webauthn.get"
    end
  end

  def create?
    !!creation_options
  end

  def get?
    !create? && !!request_options
  end

  def user_present?
    if context[:user_present].nil?
      true
    else
      context[:user_present]
    end
  end

  def rp_id
    @rp_id ||=
      if create?
        creation_options[:rp_id] || "localhost"
      elsif get?
        request_options[:rp_id] || "localhost"
      end
  end

  def challenge
    @challenge ||=
      if create?
        creation_options[:challenge] || fake_challenge
      elsif get?
        request_options[:challenge] || fake_challenge
      end
  end

  def origin
    @origin ||= context[:origin] || fake_origin
  end

  def encode(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
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
