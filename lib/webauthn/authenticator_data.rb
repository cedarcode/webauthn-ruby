# frozen_string_literal: true

require "webauthn/authenticator_data/attested_credential_data"

module WebAuthn
  class AuthenticatorData
    RP_ID_HASH_POSITION = 0

    RP_ID_HASH_LENGTH = 32
    FLAGS_LENGTH = 1
    SIGN_COUNT_LENGTH = 4

    USER_PRESENT_FLAG_POSITION = 0
    ATTESTED_CREDENTIAL_DATA_INCLUDED_FLAG_POSITION = 6

    def initialize(data)
      @data = data
    end

    def valid?
      if attested_credential_data_included?
        data.length > base_length && attested_credential_data.valid?
      else
        data.length == base_length
      end
    end

    def user_present?
      flags[USER_PRESENT_FLAG_POSITION] == "1"
    end

    def rp_id_hash
      @rp_id_hash ||=
        if valid?
          data_at(RP_ID_HASH_POSITION, RP_ID_HASH_LENGTH)
        end
    end

    def credential
      attested_credential_data.credential
    end

    private

    attr_reader :data

    def attested_credential_data
      @attested_credential_data ||=
        AttestedCredentialData.new(data_at(attested_credential_data_position))
    end

    def attested_credential_data_position
      base_length
    end

    def base_length
      RP_ID_HASH_LENGTH + FLAGS_LENGTH + SIGN_COUNT_LENGTH
    end

    def flags
      @flags ||= data_at(flags_position, FLAGS_LENGTH).unpack("b*").first
    end

    def flags_position
      RP_ID_HASH_LENGTH
    end

    def attested_credential_data_included?
      flags[ATTESTED_CREDENTIAL_DATA_INCLUDED_FLAG_POSITION] == "1"
    end

    def data_at(position, length = nil)
      length ||= data.size - position

      data[position..(position + length - 1)]
    end
  end
end
