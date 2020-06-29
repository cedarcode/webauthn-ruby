# frozen_string_literal: true

require "spec_helper"
require "support/seeds"

require "base64"
require "webauthn/authenticator_attestation_response"
require "openssl"

RSpec.describe WebAuthn::AuthenticatorAttestationResponse do
  let(:original_challenge) { fake_challenge }
  let(:origin) { fake_origin }

  let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }
  let(:attestation_response) do
    response = public_key_credential["response"]

    WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: response["attestationObject"],
      client_data_json: response["clientDataJSON"]
    )
  end

  let(:public_key_credential) { client.create(challenge: original_challenge) }

  before do
    WebAuthn.configuration.origin = origin
  end

  context "when everything's in place" do
    it "verifies" do
      expect(attestation_response.verify(original_challenge)).to be_truthy
    end

    it "is valid" do
      expect(attestation_response.valid?(original_challenge)).to be_truthy
    end

    # TODO: let FakeClient#create recieve a fixed credential
    # https://github.com/cedarcode/webauthn-ruby/pull/302#discussion_r365338434
    it "returns the credential" do
      credential = attestation_response.credential

      expect(credential.id.class).to eq(BinData::String)
      expect(credential.id.encoding).to eq(Encoding::BINARY)
      expect(credential.public_key.class).to eq(String)
      expect(credential.public_key.encoding).to be(Encoding::BINARY)
    end
  end

  context "when fido-u2f attestation" do
    let(:original_challenge) do
      Base64.strict_decode64(seeds[:security_key_direct][:credential_creation_options][:challenge])
    end

    let(:origin) { "http://localhost:3000" }

    let(:attestation_response) do
      response = seeds[:security_key_direct][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    before do
      WebAuthn.configuration.attestation_root_certificates_finders = finder_for('feitian_ft_fido_0200.pem')
    end

    it "verifies" do
      expect(attestation_response.verify(original_challenge)).to be_truthy
    end

    it "is valid" do
      expect(attestation_response.valid?(original_challenge)).to eq(true)
    end

    it "returns attestation info" do
      attestation_response.valid?(original_challenge)

      expect(attestation_response.attestation_type).to eq("Basic_or_AttCA")
      expect(attestation_response.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
    end

    it "returns the credential" do
      expect(attestation_response.credential.id.length).to be >= 16
    end

    it "returns the attestation certificate key" do
      expect(attestation_response.attestation_certificate_key_id).to(
        eq("f4b64a68c334e901b8e23c6e66e6866c31931f5d")
      )
    end
  end

  context "when packed attestation (self attestation)" do
    let(:origin) { "https://localhost:13010" }

    let(:original_challenge) do
      Base64.strict_decode64(
        seeds[:security_key_packed_self][:credential_creation_options][:challenge]
      )
    end

    let(:attestation_response) do
      response = seeds[:security_key_packed_self][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    it "verifies" do
      expect(attestation_response.verify(original_challenge)).to be_truthy
    end

    it "is valid" do
      expect(attestation_response.valid?(original_challenge)).to eq(true)
    end

    it "returns attestation info" do
      attestation_response.valid?(original_challenge)

      expect(attestation_response.attestation_type).to eq("Self")
      expect(attestation_response.attestation_trust_path).to eq(nil)
    end

    it "returns credential" do
      expect(attestation_response.credential.id.length).to be >= 16
    end

    it "returns no zeroed AAGUID" do
      expect(attestation_response.aaguid).to be_nil
    end
  end

  context "when packed attestation (basic attestation)" do
    let(:origin) { "http://localhost:3000" }

    let(:original_challenge) do
      Base64.strict_decode64(
        seeds[:security_key_packed_x5c][:credential_creation_options][:challenge]
      )
    end

    let(:attestation_response) do
      response = seeds[:security_key_packed_x5c][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    before do
      WebAuthn.configuration.attestation_root_certificates_finders = finder_for('yubico_u2f_root.pem')
    end

    it "verifies" do
      expect(attestation_response.verify(original_challenge)).to be_truthy
    end

    it "is valid" do
      expect(attestation_response.valid?(original_challenge)).to eq(true)
    end

    it "returns attestation info" do
      attestation_response.valid?(original_challenge)

      expect(attestation_response.attestation_type).to eq("Basic_or_AttCA")
      expect(attestation_response.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
    end

    it "returns credential" do
      expect(attestation_response.credential.id.length).to be >= 16
    end

    it "returns the AAGUID" do
      expect(attestation_response.aaguid).to eq("f8a011f3-8c0a-4d15-8006-17111f9edc7d")
    end
  end

  context "when TPM attestation" do
    let(:origin) { seeds[:tpm][:origin] }
    let(:time) { Time.utc(2019, 8, 13, 22, 6) }
    let(:challenge) { Base64.strict_decode64(seeds[:tpm][:credential_creation_options][:challenge]) }

    let(:attestation_response) do
      response = seeds[:tpm][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    before do
      WebAuthn.configure do |config|
        config.algorithms.concat(%w(RS1))
      end

      # TODO: Reinstate when testing TPM certs configuration
      #
      # WebAuthn.configuration.attestation_root_certificates_finders =
      #   finder_for('microsoft_tpm_root_certificate_authority_2014.cer')

      # allow(attestation_response.attestation_statement).to receive(:time).and_return(time)
      # allow(attestation_response).to receive(:attestation_root_certificates_store).and_wrap_original do |m, *args|
      #   store = m.call(*args)
      #   store.time = time
      #   store
      # end
    end

    it "verifies" do
      expect(attestation_response.verify(challenge, origin)).to be_truthy
    end

    it "is valid" do
      expect(attestation_response.valid?(challenge, origin)).to eq(true)
    end

    it "returns attestation info" do
      attestation_response.valid?(challenge, origin)

      expect(attestation_response.attestation_type).to eq("AttCA")
      expect(attestation_response.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
    end

    it "returns credential" do
      expect(attestation_response.credential.id.length).to be >= 16
    end

    it "returns the AAGUID" do
      expect(attestation_response.aaguid).to eq("08987058-cadc-4b81-b6e1-30de50dcbe96")
    end
  end

  context "when android-safetynet attestation" do
    let(:time) { Time.utc(2019, 7, 7, 16, 15, 11) }

    let(:origin) { "https://7f41ac45.ngrok.io" }

    let(:original_challenge) do
      Base64.strict_decode64(seeds[:android_safetynet_direct][:credential_creation_options][:challenge])
    end

    let(:attestation_response) do
      response = seeds[:android_safetynet_direct][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    before do
      allow(attestation_response.attestation_statement).to receive(:time).and_return(time)
      allow(attestation_response).to receive(:attestation_root_certificates_store).and_wrap_original do |m, *args|
        store = m.call(*args)
        store.time = time
        store
      end
    end

    it "verifies" do
      expect(attestation_response.verify(original_challenge)).to be_truthy
    end

    it "is valid" do
      expect(attestation_response.valid?(original_challenge)).to eq(true)
    end

    it "returns attestation info" do
      attestation_response.valid?(original_challenge)

      expect(attestation_response.attestation_type).to eq("Basic")
      expect(attestation_response.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
    end

    it "returns the credential" do
      expect(attestation_response.credential.id.length).to be >= 16
    end

    it "returns the AAGUID" do
      expect(attestation_response.aaguid).to eq("b93fd961-f2e6-462f-b122-82002247de78")
    end
  end

  context "when android-key attestation" do
    let(:origin) { seeds[:android_key_direct][:origin] }

    let(:original_challenge) do
      Base64.urlsafe_decode64(seeds[:android_key_direct][:credential_creation_options][:challenge])
    end

    let(:attestation_response) do
      response = seeds[:android_key_direct][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.urlsafe_decode64(response[:attestation_object]),
        client_data_json: Base64.urlsafe_decode64(response[:client_data_json])
      )
    end

    before do
      WebAuthn.configuration.attestation_root_certificates_finders = finder_for('android_key_root.pem')
    end

    it "verifies" do
      expect(attestation_response.verify(original_challenge)).to be_truthy
    end

    it "is valid" do
      expect(attestation_response.valid?(original_challenge)).to eq(true)
    end

    it "returns attestation info" do
      attestation_response.valid?(original_challenge)

      expect(attestation_response.attestation_type).to eq("Basic")
      expect(attestation_response.attestation_trust_path).to all(be_kind_of(OpenSSL::X509::Certificate))
    end

    it "returns the credential" do
      expect(attestation_response.credential.id.length).to be >= 16
    end

    it "returns the AAGUID" do
      expect(attestation_response.aaguid).to eq("550e4b54-aa47-409f-9a95-1ab76c130131")
    end
  end

  it "returns user-friendly error if no client data received" do
    attestation_response = WebAuthn::AuthenticatorAttestationResponse.new(
      attestation_object: "",
      client_data_json: nil
    )

    expect {
      attestation_response.valid?("", "")
    }.to raise_exception(WebAuthn::ClientDataMissingError)
  end

  describe "origin validation" do
    let(:origin) { "http://localhost" }
    let(:original_challenge) { fake_challenge }

    let(:attestation_response) do
      client = WebAuthn::FakeClient.new(actual_origin, encoding: false)
      response = client.create(challenge: original_challenge)["response"]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: response["attestationObject"],
        client_data_json: response["clientDataJSON"]
      )
    end

    context "matches the default one" do
      let(:actual_origin) { "http://localhost" }

      it "verifies" do
        expect(attestation_response.verify(original_challenge)).to be_truthy
      end

      it "is valid" do
        expect(attestation_response.valid?(original_challenge)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:actual_origin) { "http://invalid" }

      it "doesn't verify" do
        expect {
          attestation_response.verify(original_challenge)
        }.to raise_exception(WebAuthn::OriginVerificationError)
      end

      it "isn't valid" do
        expect(attestation_response.valid?(original_challenge)).to be_falsy
      end
    end
  end

  describe "rp_id validation" do
    let(:original_challenge) { fake_challenge }

    let(:attestation_response) do
      client = WebAuthn::FakeClient.new(origin, encoding: false)
      response = client.create(challenge: original_challenge, rp_id: rp_id)["response"]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: response["attestationObject"],
        client_data_json: response["clientDataJSON"]
      )
    end

    context "matches the default one" do
      let(:rp_id) { "localhost" }

      it "verifies" do
        expect(attestation_response.verify(original_challenge)).to be_truthy
      end

      it "is valid" do
        expect(attestation_response.valid?(original_challenge)).to be_truthy
      end
    end

    context "doesn't match the default one" do
      let(:rp_id) { "invalid" }

      it "doesn't verify" do
        expect {
          attestation_response.verify(original_challenge)
        }.to raise_exception(WebAuthn::RpIdVerificationError)
      end

      it "is invalid" do
        expect(attestation_response.valid?(original_challenge)).to be_falsy
      end
    end

    context "matches the one explicitly given" do
      let(:rp_id) { "custom" }

      before do
        WebAuthn.configuration.rp_id = rp_id
      end

      it "verifies" do
        expect(attestation_response.verify(original_challenge)).to be_truthy
      end

      it "is valid" do
        expect(attestation_response.valid?(original_challenge)).to be_truthy
      end
    end
  end

  describe "tokenBinding validation" do
    let(:client) { WebAuthn::FakeClient.new(origin, token_binding: token_binding, encoding: false) }

    context "it has stuff" do
      let(:token_binding) { { status: "supported" } }

      it "verifies" do
        expect(attestation_response.verify(original_challenge, origin)).to be_truthy
      end

      it "is valid" do
        expect(attestation_response.valid?(original_challenge, origin)).to be_truthy
      end
    end

    context "has an invalid format" do
      let(:token_binding) { "invalid token binding format" }

      it "doesn't verify" do
        expect {
          attestation_response.verify(original_challenge, origin)
        }.to raise_exception(WebAuthn::TokenBindingVerificationError)
      end

      it "isn't valid" do
        expect(attestation_response.valid?(original_challenge, origin)).to be_falsy
      end
    end
  end

  describe "user verification" do
    context "when UV is not set" do
      let(:public_key_credential) { client.create(challenge: original_challenge, user_verified: false) }

      it "doesn't verify if user verification is required" do
        expect {
          attestation_response.verify(original_challenge, origin, user_verification: true)
        }.to raise_exception(WebAuthn::UserVerifiedVerificationError)
      end
    end
  end

  describe "attested credential data verification" do
    context "when AT is not set" do
      let(:public_key_credential) { client.create(challenge: original_challenge, attested_credential_data: false) }

      it "doesn't verify" do
        expect {
          attestation_response.verify(original_challenge, origin)
        }.to raise_exception(WebAuthn::AttestedCredentialVerificationError)
      end
    end

    context "when credential algorithm is not what expected" do
      before do
        WebAuthn.configuration.algorithms = ["RS256"]
      end

      it "doesn't verify" do
        expect {
          attestation_response.verify(original_challenge, origin)
        }.to raise_exception(WebAuthn::AttestedCredentialVerificationError)
      end
    end
  end

  describe "attestation statement verification" do
    let(:original_challenge) do
      Base64.strict_decode64(seeds[:security_key_direct][:credential_creation_options][:challenge])
    end

    let(:origin) { "http://localhost:3000" }

    let(:attestation_response) do
      response = seeds[:security_key_direct][:authenticator_attestation_response]

      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: Base64.strict_decode64(response[:attestation_object]),
        client_data_json: Base64.strict_decode64(response[:client_data_json])
      )
    end

    before do
      attestation_response.attestation_statement.instance_variable_get(:@statement)["sig"] =
        "corrupted signature".b
    end

    context "when verification is set to true" do
      before do
        WebAuthn.configuration.verify_attestation_statement = true
      end

      it "verifies the attestation statement" do
        expect { attestation_response.verify(original_challenge) }.to raise_error(OpenSSL::PKey::PKeyError)
      end
    end

    context "when verification is set to false" do
      before do
        WebAuthn.configuration.verify_attestation_statement = false
      end

      it "does not verify the attestation statement" do
        expect(attestation_response.verify(original_challenge)).to be_truthy
      end
    end
  end
end
