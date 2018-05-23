# frozen_string_literal: true

module WebAuthn
  class AuthenticatorData
    RP_ID_HASH_POSITION = 0

    MIN_LENGTH = 37
    RP_ID_HASH_LENGTH = 32
    FLAGS_LENGTH = 1
    SIGN_COUNT_LENGTH = 4
    AAGUID_LENGTH = 16
    CREDENTIAL_ID_LENGTH_LENGTH = 2

    USER_PRESENT_FLAG_POSITION = 0
    ATTESTED_CREDENTIAL_DATA_INCLUDED_FLAG_POSITION = 6

    UINT16_BIG_ENDIAN_FORMAT = "n*"

    def initialize(data)
      @data = data
    end

    def valid?
      data.length >= MIN_LENGTH
    end

    def user_present?
      flags[USER_PRESENT_FLAG_POSITION] == "1"
    end

    def rp_id_hash
      if valid?
        data_at(RP_ID_HASH_POSITION, RP_ID_HASH_LENGTH)
      end
    end

    def credential_id
      if attested_credential_data_included?
        data_at(credential_id_position, credential_id_length)
      end
    end

    def credential_public_key
      CBOR.decode(data_at(credential_public_key_position, credential_public_key_length))
    end

    private

    attr_reader :data

    def flags
      @flags ||= data_at(flags_position, FLAGS_LENGTH).unpack("b*").first
    end

    def flags_position
      RP_ID_HASH_LENGTH
    end

    def attested_credential_data_included?
      flags[ATTESTED_CREDENTIAL_DATA_INCLUDED_FLAG_POSITION] == "1"
    end

    def credential_id_position
      credential_id_length_position + CREDENTIAL_ID_LENGTH_LENGTH
    end

    def credential_id_length
      data_at(credential_id_length_position, CREDENTIAL_ID_LENGTH_LENGTH).
        unpack(UINT16_BIG_ENDIAN_FORMAT).
        first
    end

    def credential_id_length_position
      RP_ID_HASH_LENGTH + FLAGS_LENGTH + SIGN_COUNT_LENGTH + AAGUID_LENGTH
    end

    def credential_public_key_position
      credential_id_position + credential_id_length
    end

    def credential_public_key_length
      data.size - (
        RP_ID_HASH_LENGTH +
        FLAGS_LENGTH +
        SIGN_COUNT_LENGTH +
        AAGUID_LENGTH +
        CREDENTIAL_ID_LENGTH_LENGTH +
        credential_id_length
      )
    end

    def data_at(position, length)
      data[position..(position + length - 1)]
    end
  end
end
