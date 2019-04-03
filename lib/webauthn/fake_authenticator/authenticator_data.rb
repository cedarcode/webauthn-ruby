# frozen_string_literal: true

require "cose/key"
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

      def cose_credential_public_key
        alg = {
          COSE::Key::EC2::CRV_P256 => -7,
          COSE::Key::EC2::CRV_P384 => -35,
          COSE::Key::EC2::CRV_P521 => -36
        }

        key = COSE::Key::EC2.from_pkey(credential[:public_key])

        # FIXME: Remove once writer in cose
        key.instance_variable_set(:@alg, alg[key.crv])

        key.serialize
      end

      def key_bytes(public_key)
        public_key.to_bn.to_s(2)
      end
    end
  end
end
