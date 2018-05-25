# frozen_string_literal: true

require "webauthn/authenticator_data/attested_credential_data/public_key_u2f"

module WebAuthn
  class AuthenticatorData
    class AttestedCredentialData
      AAGUID_LENGTH = 16
      ID_LENGTH_LENGTH = 2

      UINT16_BIG_ENDIAN_FORMAT = "n*"

      def initialize(data)
        @data = data
      end

      def valid?
        data.length >= AAGUID_LENGTH + ID_LENGTH_LENGTH && public_key.valid?
      end

      def id
        data_at(id_position, id_length)
      end

      def public_key
        @public_key ||= PublicKeyU2f.new(data_at(public_key_position, public_key_length))
      end

      private

      attr_reader :data

      def id_position
        id_length_position + ID_LENGTH_LENGTH
      end

      def id_length
        @id_length ||=
          data_at(id_length_position, ID_LENGTH_LENGTH)
          .unpack(UINT16_BIG_ENDIAN_FORMAT)
          .first
      end

      def id_length_position
        AAGUID_LENGTH
      end

      def public_key_position
        id_position + id_length
      end

      def public_key_length
        data.size - (AAGUID_LENGTH + ID_LENGTH_LENGTH + id_length)
      end

      def data_at(position, length = nil)
        length ||= data.size - position

        data[position..(position + length - 1)]
      end
    end
  end
end
