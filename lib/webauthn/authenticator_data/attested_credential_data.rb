# frozen_string_literal: true

require "bindata"
require "cose/key"
require "webauthn/error"

module WebAuthn
  class AttestedCredentialDataFormatError < WebAuthn::Error; end

  class AuthenticatorData < BinData::Record
    class AttestedCredentialData < BinData::Record
      AAGUID_LENGTH = 16
      ZEROED_AAGUID = 0.chr * AAGUID_LENGTH

      ID_LENGTH_LENGTH = 2

      endian :big

      string :raw_aaguid, length: AAGUID_LENGTH
      bit16 :id_length
      string :id, read_length: :id_length
      count_bytes_remaining :trailing_bytes_length
      string :trailing_bytes, length: :trailing_bytes_length

      # TODO: use keyword_init when we dropped Ruby 2.4 support
      Credential =
        Struct.new(:id, :public_key, :algorithm) do
          def public_key_object
            COSE::Key.deserialize(public_key).to_pkey
          end
        end

      def self.deserialize(data)
        read(data)
      rescue EOFError
        raise AttestedCredentialDataFormatError
      end

      def valid?
        valid_credential_public_key?
      end

      def aaguid
        raw_aaguid.unpack("H8H4H4H4H12").join("-")
      end

      def credential
        @credential ||=
          if valid?
            Credential.new(id, public_key, algorithm)
          end
      end

      def length
        if valid?
          AAGUID_LENGTH + ID_LENGTH_LENGTH + id_length + public_key_length
        end
      end

      private

      def algorithm
        COSE::Algorithm.find(cose_key.alg).name
      end

      def valid_credential_public_key?
        !!cose_key.alg
      end

      def cose_key
        @cose_key ||= COSE::Key.deserialize(public_key)
      end

      def public_key
        trailing_bytes[0..public_key_length - 1]
      end

      def public_key_length
        @public_key_length ||=
          CBOR.encode(CBOR::Unpacker.new(StringIO.new(trailing_bytes)).each.first).length
      end
    end
  end
end
