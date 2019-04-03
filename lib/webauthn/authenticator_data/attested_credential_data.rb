# frozen_string_literal: true

require "cose/key"

module WebAuthn
  class AuthenticatorData
    class AttestedCredentialData
      AAGUID_LENGTH = 16

      ID_LENGTH_LENGTH = 2

      UINT16_BIG_ENDIAN_FORMAT = "n*"

      # FIXME: use keyword_init when we dropped Ruby 2.4 support
      Credential = Struct.new(:id, :public_key) do
        def public_key_object
          COSE::Key.deserialize(public_key).to_pkey
        end
      end

      def initialize(data)
        @data = data
      end

      def valid?
        data.length >= AAGUID_LENGTH + ID_LENGTH_LENGTH && valid_credential_public_key?
      end

      def aaguid
        data_at(0, AAGUID_LENGTH)
      end

      def credential
        @credential ||=
          if id
            Credential.new(id, public_key)
          end
      end

      def length
        if valid?
          public_key_position + public_key_length
        end
      end

      private

      attr_reader :data

      def valid_credential_public_key?
        cose_key = COSE::Key.deserialize(public_key)

        !!cose_key.alg
      end

      def id
        if valid?
          data_at(id_position, id_length)
        end
      end

      def public_key
        @public_key ||= data_at(public_key_position, public_key_length)
      end

      def id_position
        id_length_position + ID_LENGTH_LENGTH
      end

      def id_length
        @id_length ||= data_at(id_length_position, ID_LENGTH_LENGTH).unpack(UINT16_BIG_ENDIAN_FORMAT)[0]
      end

      def id_length_position
        AAGUID_LENGTH
      end

      def public_key_position
        id_position + id_length
      end

      def public_key_length
        @public_key_length ||=
          CBOR.encode(CBOR::Unpacker.new(StringIO.new(data_at(public_key_position))).each.first).length
      end

      def data_at(position, length = nil)
        length ||= data.size - position

        data[position..(position + length - 1)]
      end
    end
  end
end
