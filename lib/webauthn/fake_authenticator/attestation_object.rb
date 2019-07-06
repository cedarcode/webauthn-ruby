# frozen_string_literal: true

require "cbor"
require "webauthn/fake_authenticator/authenticator_data"

module WebAuthn
  class FakeAuthenticator
    class AttestationObject
      def initialize(
        client_data_hash:,
        rp_id_hash:,
        credential_id:,
        credential_key:,
        user_present: true,
        user_verified: false,
        attested_credential_data: true,
        sign_count: 0
      )
        @client_data_hash = client_data_hash
        @rp_id_hash = rp_id_hash
        @credential_id = credential_id
        @credential_key = credential_key
        @user_present = user_present
        @user_verified = user_verified
        @attested_credential_data = attested_credential_data
        @sign_count = sign_count
      end

      def serialize
        CBOR.encode(
          "fmt" => "none",
          "attStmt" => {},
          "authData" => authenticator_data.serialize
        )
      end

      private

      attr_reader(
        :client_data_hash,
        :rp_id_hash,
        :credential_id,
        :credential_key,
        :user_present,
        :user_verified,
        :attested_credential_data,
        :sign_count
      )

      def authenticator_data
        @authenticator_data ||=
          begin
            credential_data =
              if attested_credential_data
                { id: credential_id, public_key: credential_key.public_key }
              end

            AuthenticatorData.new(
              rp_id_hash: rp_id_hash,
              credential: credential_data,
              user_present: user_present,
              user_verified: user_verified,
              sign_count: 0
            )
          end
      end
    end
  end
end
