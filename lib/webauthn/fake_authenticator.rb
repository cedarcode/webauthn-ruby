# frozen_string_literal: true

require "cbor"
require "openssl"
require "securerandom"

module WebAuthn
  class FakeAuthenticator
    class Base
      def initialize(challenge: fake_challenge, rp_id: "localhost", sign_count: 0, context: {})
        @challenge = challenge
        @rp_id = rp_id
        @sign_count = sign_count
        @context = context
      end

      def authenticator_data
        @authenticator_data ||= rp_id_hash + raw_flags + raw_sign_count + attested_credential_data + extension_data
      end

      def client_data_json
        @client_data_json ||= { challenge: encode(challenge), origin: origin, type: type }.to_json
      end

      def credential_key
        @credential_key ||= OpenSSL::PKey::EC.new("prime256v1").generate_key
      end

      def credential_id
        @credential_id ||= SecureRandom.random_bytes(16)
      end

      def rp_id_hash
        OpenSSL::Digest::SHA256.digest(rp_id)
      end

      private

      attr_reader :challenge, :context, :rp_id

      def raw_flags
        [
          [
            bit(:user_present),
            "0",
            bit(:user_verified),
            "000",
            attested_credential_data_present_bit,
            extension_data_present_bit
          ].join
        ].pack("b*")
      end

      def attested_credential_data_present_bit
        if attested_credential_data.empty?
          "0"
        else
          "1"
        end
      end

      def extension_data_present_bit
        if extension_data.empty?
          "0"
        else
          "1"
        end
      end

      def attested_credential_data
        ""
      end

      def extension_data
        ""
      end

      def raw_sign_count
        [@sign_count].pack('L>')
      end

      def bit(flag)
        if context[flag].nil? || context[flag]
          "1"
        else
          "0"
        end
      end

      def origin
        @origin ||= context[:origin] || fake_origin
      end

      def encode(bytes)
        Base64.urlsafe_encode64(bytes, padding: false)
      end

      def fake_challenge
        SecureRandom.random_bytes(32)
      end

      def fake_origin
        "http://localhost"
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

      def cose_credential_public_key
        fake_cose_credential_key(
          x_coordinate: key_bytes(credential_key.public_key)[1..32],
          y_coordinate: key_bytes(credential_key.public_key)[33..64]
        )
      end

      def type
        "webauthn.create"
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
    end

    class Get < Base
      def signature
        @signature ||= credential_key.sign(
          "SHA256",
          authenticator_data + OpenSSL::Digest::SHA256.digest(client_data_json)
        )
      end

      private

      def type
        "webauthn.get"
      end
    end
  end
end
