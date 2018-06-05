# frozen_string_literal: true

class FakeAuthenticator
  def initialize(creation_options: nil, request_options: nil, context: {})
    @creation_options = creation_options
    @request_options = request_options
    @context = context
  end

  def authenticator_data
    @authenticator_data ||= rp_id_hash + raw_flags + raw_sign_count + attested_credential_data
  end

  def client_data_json
    @client_data_json ||= { challenge: encode(challenge), origin: origin, type: type }.to_json
  end

  def credential_key
    @credential_key ||= OpenSSL::PKey::EC.new("prime256v1").generate_key
  end

  def signature
    @signature ||=
      if create?
        # TODO Implement signing for when creating credential
      elsif get?
        credential_key.sign("SHA256", authenticator_data + OpenSSL::Digest::SHA256.digest(client_data_json))
      end
  end

  def attestation_object
    if create?
      CBOR.encode(
        "fmt" => "none",
        "attStmt" => {},
        "authData" => authenticator_data
      )
    end
  end

  private

  attr_reader :creation_options, :context, :request_options

  def rp_id_hash
    OpenSSL::Digest::SHA256.digest(rp_id)
  end

  def raw_flags
    ["#{user_present_bit}00000#{attested_credential_data_present_bit}0"].pack("b*")
  end

  def attested_credential_data_present_bit
    if attested_credential_data.length > 0
      "1"
    else
      "0"
    end
  end

  def attested_credential_data
    if create?
      aaguid + [credential_id.length].pack("n*") + credential_id + cose_credential_public_key
    else
      ""
    end
  end

  def cose_credential_public_key
    CBOR.encode(
      -2 => key_bytes(credential_key.public_key)[1..32],
      -3 => key_bytes(credential_key.public_key)[33..64]
    )
  end

  def credential_id
    @credential_id ||= SecureRandom.random_bytes(16)
  end

  def aaguid
    @aaguid ||= SecureRandom.random_bytes(16)
  end

  def raw_sign_count
    "0000"
  end

  def user_present_bit
    if user_present?
      "1"
    else
      "0"
    end
  end

  def type
    if create?
      "webauthn.create"
    elsif get?
      "webauthn.get"
    end
  end

  def create?
    !!creation_options
  end

  def get?
    !create? && !!request_options
  end

  def user_present?
    if context[:user_present].nil?
      true
    else
      context[:user_present]
    end
  end

  def rp_id
    @rp_id ||=
      if create?
        creation_options[:rp_id] || "localhost"
      elsif get?
        request_options[:rp_id] || "localhost"
      end
  end

  def challenge
    @challenge ||=
      if create?
        creation_options[:challenge] || fake_challenge
      elsif get?
        request_options[:challenge] || fake_challenge
      end
  end

  def origin
    @origin ||= context[:origin] || fake_origin
  end

  def encode(bytes)
    Base64.urlsafe_encode64(bytes, padding: false)
  end
end
