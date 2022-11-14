# frozen_string_literal: true

require "cose/key"
require "cbor"
require "securerandom"

module WebAuthn
  class FakeAuthenticator
    class AuthenticatorData
      AAGUID = SecureRandom.random_bytes(16)

      attr_reader :sign_count

      def initialize(
        rp_id_hash:,
        credential: {
          id: SecureRandom.random_bytes(16),
          public_key: OpenSSL::PKey::EC.generate("prime256v1").public_key
        },
        sign_count: 0,
        user_present: true,
        user_verified: !user_present,
        backup_eligibility: false,
        backup_state: false,
        aaguid: AAGUID,
        extensions: { "fakeExtension" => "fakeExtensionValue" }
      )
        @rp_id_hash = rp_id_hash
        @credential = credential
        @sign_count = sign_count
        @user_present = user_present
        @user_verified = user_verified
        @backup_eligibility = backup_eligibility
        @backup_state = backup_state
        @aaguid = aaguid
        @extensions = extensions
      end

      def serialize
        rp_id_hash + flags + serialized_sign_count + attested_credential_data + extension_data
      end

      private

      attr_reader :rp_id_hash,
                  :credential,
                  :user_present,
                  :user_verified,
                  :extensions,
                  :backup_eligibility,
                  :backup_state

      def flags
        [
          [
            bit(:user_present),
            reserved_for_future_use_bit,
            bit(:user_verified),
            bit(:backup_eligibility),
            bit(:backup_state),
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
            @aaguid +
              [credential[:id].length].pack("n*") +
              credential[:id] +
              cose_credential_public_key
          else
            ""
          end
      end

      def extension_data
        if extensions
          CBOR.encode(extensions)
        else
          ""
        end
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
        if extension_data.empty?
          "0"
        else
          "1"
        end
      end

      def reserved_for_future_use_bit
        "0"
      end

      def context
        {
          user_present: user_present,
          user_verified: user_verified,
          backup_eligibility: backup_eligibility,
          backup_state: backup_state
        }
      end

      def cose_credential_public_key
        case credential[:public_key]
        when OpenSSL::PKey::RSA
          key = COSE::Key::RSA.from_pkey(credential[:public_key])
          key.alg = -257
        when OpenSSL::PKey::EC::Point
          alg = {
            COSE::Key::Curve.by_name("P-256").id => -7,
            COSE::Key::Curve.by_name("P-384").id => -35,
            COSE::Key::Curve.by_name("P-521").id => -36
          }

          key = COSE::Key::EC2.from_pkey(credential[:public_key])
          key.alg = alg[key.crv]

        end

        key.serialize
      end

      def key_bytes(public_key)
        public_key.to_bn.to_s(2)
      end
    end
  end
end
