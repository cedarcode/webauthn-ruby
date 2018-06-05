# frozen_string_literal: true

class FakeAuthenticator
  class Base
    def initialize(challenge: fake_challenge, rp_id: "localhost", context: {})
      @challenge = challenge
      @rp_id = rp_id
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

    private

    attr_reader :challenge, :context, :rp_id

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
      ""
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

    def user_present?
      if context[:user_present].nil?
        true
      else
        context[:user_present]
      end
    end

    def origin
      @origin ||= context[:origin] || fake_origin
    end

    def encode(bytes)
      Base64.urlsafe_encode64(bytes, padding: false)
    end
  end

  class Create < Base
    def attestation_object
      CBOR.encode(
        "fmt" => "none",
        "attStmt" => {},
        "authData" => authenticator_data
      )
    end

    private

    def attested_credential_data
      aaguid + [credential_id.length].pack("n*") + credential_id + cose_credential_public_key
    end

    def aaguid
      @aaguid ||= SecureRandom.random_bytes(16)
    end

    def credential_id
      @credential_id ||= SecureRandom.random_bytes(16)
    end

    def cose_credential_public_key
      CBOR.encode(
        -2 => key_bytes(credential_key.public_key)[1..32],
        -3 => key_bytes(credential_key.public_key)[33..64]
      )
    end

    def type
      "webauthn.create"
    end
  end

  class Get < Base
    def signature
      @signature ||= credential_key.sign("SHA256", authenticator_data + OpenSSL::Digest::SHA256.digest(client_data_json))
    end

    private

    def type
      "webauthn.get"
    end
  end
end
