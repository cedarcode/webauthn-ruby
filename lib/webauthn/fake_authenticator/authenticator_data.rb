# frozen_string_literal: true

require "cbor"
require "securerandom"

module WebAuthn
  class FakeAuthenticator
    class AuthenticatorData
      def initialize(rp_id_hash:, credential: nil, sign_count: 0, user_present: true, user_verified: !user_present)
        @rp_id_hash = rp_id_hash
        @credential = credential
        @sign_count = sign_count
        @user_present = user_present
        @user_verified = user_verified
      end

      def serialize
        rp_id_hash + flags + serialized_sign_count + attested_credential_data + extensions
      end

      private

      attr_reader :rp_id_hash, :credential, :sign_count, :user_present, :user_verified

      def flags
        [
          [
            bit(:user_present),
            reserved_for_future_use_bit,
            bit(:user_verified),
            reserved_for_future_use_bit,
            reserved_for_future_use_bit,
            reserved_for_future_use_bit,
            attested_credential_data_included_bit,
            extension_data_included_bit
          ].join
        ].pack("b*")
      end

      def serialized_sign_count
        [sign_count].pack('L>')
      end

      def attested_credential_data
        @attested_credential_data ||=
          if credential
            WebAuthn::FakeAuthenticator::AAGUID +
              [credential[:id].length].pack("n*") +
              credential[:id] +
              cose_credential_public_key
          else
            ""
          end
      end

      def cose_credential_public_key
        fake_cose_credential_key(
          x_coordinate: key_bytes(credential[:public_key])[1..32],
          y_coordinate: key_bytes(credential[:public_key])[33..64]
        )
      end

      def extensions
        CBOR.encode("fakeExtension" => "fakeExtensionValue")
      end

      def bit(flag)
        if context[flag]
          "1"
        else
          "0"
        end
      end

      def attested_credential_data_included_bit
        if attested_credential_data.empty?
          "0"
        else
          "1"
        end
      end

      def extension_data_included_bit
        if extensions.empty?
          "0"
        else
          "1"
        end
      end

      def reserved_for_future_use_bit
        "0"
      end

      def context
        { user_present: user_present, user_verified: user_verified }
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
  end
end
