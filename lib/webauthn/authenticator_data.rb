# frozen_string_literal: true

require "bindata"
require "webauthn/authenticator_data/attested_credential_data"
require "webauthn/error"

module WebAuthn
  class AuthenticatorDataFormatError < WebAuthn::Error; end

  class AuthenticatorData < BinData::Record
    RP_ID_HASH_LENGTH = 32
    FLAGS_LENGTH = 1
    SIGN_COUNT_LENGTH = 4

    endian :big

    count_bytes_remaining :data_length
    string :rp_id_hash, length: RP_ID_HASH_LENGTH
    struct :flags do
      bit1 :extension_data_included
      bit1 :attested_credential_data_included
      bit1 :reserved_for_future_use_2
      bit1 :backup_state
      bit1 :backup_eligibility
      bit1 :user_verified
      bit1 :reserved_for_future_use_1
      bit1 :user_present
    end
    bit32 :sign_count
    count_bytes_remaining :trailing_bytes_length
    string :trailing_bytes, length: :trailing_bytes_length

    def self.deserialize(data)
      read(data)
    rescue EOFError
      raise AuthenticatorDataFormatError
    end

    def data
      to_binary_s
    end

    def valid?
      (!attested_credential_data_included? || attested_credential_data.valid?) &&
        (!extension_data_included? || extension_data) &&
        valid_length?
    end

    def user_flagged?
      user_present? || user_verified?
    end

    def user_present?
      flags.user_present == 1
    end

    def user_verified?
      flags.user_verified == 1
    end

    def credential_backup_eligible?
      flags.backup_eligibility == 1
    end

    def credential_backed_up?
      flags.backup_state == 1
    end

    def attested_credential_data_included?
      flags.attested_credential_data_included == 1
    end

    def extension_data_included?
      flags.extension_data_included == 1
    end

    def credential
      if attested_credential_data_included?
        attested_credential_data.credential
      end
    end

    def attested_credential_data
      @attested_credential_data ||=
        AttestedCredentialData.deserialize(trailing_bytes)
    rescue AttestedCredentialDataFormatError
      raise AuthenticatorDataFormatError
    end

    def extension_data
      @extension_data ||= CBOR.decode(raw_extension_data)
    end

    def aaguid
      raw_aaguid = attested_credential_data.raw_aaguid

      unless raw_aaguid == WebAuthn::AuthenticatorData::AttestedCredentialData::ZEROED_AAGUID
        attested_credential_data.aaguid
      end
    end

    private

    def valid_length?
      data_length == base_length + attested_credential_data_length + extension_data_length
    end

    def raw_extension_data
      if extension_data_included?
        if attested_credential_data_included?
          trailing_bytes[attested_credential_data.length..-1]
        else
          trailing_bytes.snapshot
        end
      end
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

    def base_length
      RP_ID_HASH_LENGTH + FLAGS_LENGTH + SIGN_COUNT_LENGTH
    end
  end
end
