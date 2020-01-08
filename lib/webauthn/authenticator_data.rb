# frozen_string_literal: true

require "webauthn/authenticator_data/attested_credential_data"

module WebAuthn
  class AuthenticatorData
    RP_ID_HASH_POSITION = 0

    RP_ID_HASH_LENGTH = 32
    FLAGS_LENGTH = 1
    SIGN_COUNT_LENGTH = 4

    SIGN_COUNT_POSITION = RP_ID_HASH_LENGTH + FLAGS_LENGTH

    USER_PRESENT_FLAG_POSITION = 0
    USER_VERIFIED_FLAG_POSITION = 2
    ATTESTED_CREDENTIAL_DATA_INCLUDED_FLAG_POSITION = 6
    EXTENSION_DATA_INCLUDED_FLAG_POSITION = 7

    def initialize(data)
      @data = data
    end

    attr_reader :data

    def valid?
      valid_length? &&
        (!attested_credential_data_included? || attested_credential_data.valid?) &&
        (!extension_data_included? || extension_data)
    end

    def user_flagged?
      user_present? || user_verified?
    end

    def user_present?
      flags[USER_PRESENT_FLAG_POSITION] == "1"
    end

    def user_verified?
      flags[USER_VERIFIED_FLAG_POSITION] == "1"
    end

    def attested_credential_data_included?
      flags[ATTESTED_CREDENTIAL_DATA_INCLUDED_FLAG_POSITION] == "1"
    end

    def extension_data_included?
      flags[EXTENSION_DATA_INCLUDED_FLAG_POSITION] == "1"
    end

    def rp_id_hash
      @rp_id_hash ||=
        if valid?
          data_at(RP_ID_HASH_POSITION, RP_ID_HASH_LENGTH)
        end
    end

    def credential
      if attested_credential_data_included?
        attested_credential_data.credential
      end
    end

    def sign_count
      @sign_count ||= data_at(SIGN_COUNT_POSITION, SIGN_COUNT_LENGTH).unpack('L>')[0]
    end

    def attested_credential_data
      @attested_credential_data ||=
        AttestedCredentialData.new(data_at(attested_credential_data_position))
    end

    def extension_data
      @extension_data ||= CBOR.decode(raw_extension_data)
    end

    def flags
      @flags ||= data_at(flags_position, FLAGS_LENGTH).unpack("b*")[0]
    end

    def aaguid
      raw_aaguid = attested_credential_data.raw_aaguid

      unless raw_aaguid == WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
        attested_credential_data.aaguid
      end
    end

    private

    def valid_length?
      data.length == base_length + attested_credential_data_length + extension_data_length
    end

    def raw_extension_data
      data_at(extension_data_position)
    end

    def attested_credential_data_position
      base_length
    end

    def attested_credential_data_length
      if attested_credential_data_included?
        attested_credential_data.length
      else
        0
      end
    end

    def extension_data_length
      if extension_data_included?
        raw_extension_data.length
      else
        0
      end
    end

    def extension_data_position
      base_length + attested_credential_data_length
    end

    def base_length
      RP_ID_HASH_LENGTH + FLAGS_LENGTH + SIGN_COUNT_LENGTH
    end

    def flags_position
      RP_ID_HASH_LENGTH
    end

    def data_at(position, length = nil)
      length ||= data.size - position

      data[position..(position + length - 1)]
    end
  end
end
