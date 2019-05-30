# frozen_string_literal: true

require "spec_helper"
require "support/seeds"
require "webauthn/attestation_statement/fido_u2f/public_key"
require "webauthn/authenticator_assertion_response"
require "webauthn/u2f_migrator"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:client) { WebAuthn::FakeClient.new(actual_origin) }

  let!(:credential) { create_credential(client: client) }
  let(:credential_id) { credential[0] }
  let(:credential_public_key) { credential[1] }

  let(:allowed_credentials) { [{ id: credential_id, public_key: credential_public_key, sign_count: 0 }] }

  let(:origin) { fake_origin }
  let(:actual_origin) { origin }
  let(:original_challenge) { fake_challenge }
  let(:assertion) { client.get(challenge: original_challenge) }
  let(:authenticator_data) { assertion[:response][:authenticator_data] }

  let(:assertion_response) do
    WebAuthn::AuthenticatorAssertionResponse.new(
      credential_id: assertion[:id],
      client_data_json: assertion[:response][:client_data_json],
      authenticator_data: authenticator_data,
      signature: assertion[:response][:signature]
    )
  end

  before do
    WebAuthn.configuration.origin = origin
  end

  context "when everything's in place" do
    it "verifies" do
      expect(assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)).to be_truthy
    end

    it "is valid" do
      expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_truthy
    end
  end

  # Gem version v1.11.0 and lower, used to behave so that Credential#public_key
  # returned an EC P-256 uncompressed point.
  #
  # Because of https://github.com/cedarcode/webauthn-ruby/issues/137 this was changed
  # and Credential#public_key started returning the unchanged COSE_Key formatted
  # credentialPublicKey (as in https://www.w3.org/TR/webauthn/#credentialpublickey).
  #
  # Given that the credential public key is expected to be stored long-term by the gem
  # user and later be passed as one of the allowed_credentials arguments in the
  # AuthenticatorAssertionResponse.verify call, we then need to support the two formats.
  context "when everything's in place with the old public key format" do
    it "verifies" do
      allowed_credentials[0][:public_key] =
        WebAuthn::AttestationStatement::FidoU2f::PublicKey
        .new(allowed_credentials[0][:public_key])
        .to_uncompressed_point

      expect(assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)).to be_truthy
    end
  end

  context "with more than one allowed credential" do
    let(:allowed_credentials) do
      [
        {
          id: credential_id,
          public_key: credential_public_key,
          sign_count: 0
        },
        {
          id: SecureRandom.random_bytes(16),
          public_key: key_bytes(OpenSSL::PKey::EC.new("prime256v1").generate_key.public_key)
        }
      ]
    end

    it "verifies" do
      expect(assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)).to be_truthy
    end

    it "is valid" do
      expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_truthy
    end
  end

  context "if signature was signed with a different key" do
    let(:credentials) do
      _different_id, different_public_key = create_credential(client: client)

      [{ id: credential_id, public_key: different_public_key }]
    end

    it "is invalid" do
      expect(assertion_response.valid?(original_challenge, allowed_credentials: credentials)).to be_falsy
    end

    it "doesn't verify" do
      expect {
        assertion_response.verify(original_challenge, allowed_credentials: credentials)
      }.to raise_exception(WebAuthn::SignatureVerificationError)
    end
  end

  context "if credential id is not among the allowed ones" do
    let(:credentials) do
      [
        {
          id: SecureRandom.random_bytes(16),
          public_key: credential_public_key
        }
      ]
    end

    it "doesn't verify" do
      expect {
        assertion_response.verify(original_challenge, allowed_credentials: credentials)
      }.to raise_exception(WebAuthn::CredentialVerificationError)
    end

    it "is invalid" do
      expect(assertion_response.valid?(original_challenge, allowed_credentials: credentials)).to be_falsy
    end
  end

  describe "type validation" do
    context "if type is create instead of get" do
      before do
        allow(client).to receive(:type_for).and_return("webauthn.create")
      end

      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
        }.to raise_exception(WebAuthn::TypeVerificationError)
      end

      it "is invalid" do
        expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_falsy
      end
    end
  end

  describe "user present validation" do
    let(:assertion) { client.get(challenge: original_challenge, user_present: false, user_verified: false) }

    context "if user flags are off" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
        }.to raise_exception(WebAuthn::UserPresenceVerificationError)
      end

      it "is invalid" do
        expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_falsy
      end
    end
  end

  describe "user verified validation" do
    context "if user flags are off" do
      let(:assertion) { client.get(challenge: original_challenge, user_present: true, user_verified: false) }

      it "doesn't verify" do
        expect {
          assertion_response.verify(
            original_challenge,
            allowed_credentials: allowed_credentials,
            user_verification: true
          )
        }.to raise_exception(WebAuthn::UserVerifiedVerificationError)
      end
    end
  end

  describe "challenge validation" do
    context "if challenge doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(fake_challenge, allowed_credentials: allowed_credentials)
        }.to raise_exception(WebAuthn::ChallengeVerificationError)
      end

      it "is invalid" do
        expect(assertion_response.valid?(fake_challenge, allowed_credentials: allowed_credentials)).to be_falsy
      end
    end
  end

  describe "origin validation" do
    context "if origin doesn't match" do
      let(:actual_origin) { "http://different-origin" }

      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
        }.to raise_exception(WebAuthn::OriginVerificationError)
      end

      it "is invalid" do
        expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_falsy
      end
    end
  end

  describe "tokenBinding validation" do
    let(:client) { WebAuthn::FakeClient.new(actual_origin, token_binding: token_binding) }

    context "it has stuff" do
      let(:token_binding) { { status: "supported" } }

      it "verifies" do
        expect(assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)).to be_truthy
      end

      it "is valid" do
        expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_truthy
      end
    end

    context "has an invalid format" do
      let(:token_binding) { "invalid token binding format" }

      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
        }.to raise_exception(WebAuthn::TokenBindingVerificationError)
      end

      it "isn't valid" do
        expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_falsy
      end
    end
  end

  describe "rp_id validation" do
    before do
      WebAuthn.configuration.rp_id = "different-rp_id"
    end

    context "if rp_id_hash doesn't match" do
      it "doesn't verify" do
        expect {
          assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
        }.to raise_exception(WebAuthn::RpIdVerificationError)
      end

      it "is invalid" do
        expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_falsy
      end
    end

    context "when correct rp_id is explicitly given" do
      it "verifies" do
        expect(
          assertion_response.verify(
            original_challenge,
            allowed_credentials: allowed_credentials,
            rp_id: URI.parse(origin).host
          )
        ).to be_truthy
      end

      it "is valid" do
        expect(
          assertion_response.valid?(
            original_challenge,
            allowed_credentials: allowed_credentials,
            rp_id: URI.parse(origin).host
          )
        ).to be_truthy
      end
    end
  end

  describe "sign_count validation" do
    context "if authenticator does not support counter" do
      let(:allowed_credentials) { [{ id: credential_id, public_key: credential_public_key, sign_count: 0 }] }
      let(:assertion) { client.get(challenge: original_challenge, sign_count: 0) }

      it "verifies" do
        expect(
          assertion_response.verify(
            original_challenge,
            allowed_credentials: allowed_credentials,
          )
        ).to be_truthy
      end
    end

    context "when the authenticator supports counter" do
      let(:allowed_credentials) { [{ id: credential_id, public_key: credential_public_key, sign_count: 5 }] }

      context "and it's greater than the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 6) }

        it "verifies" do
          expect(
            assertion_response.verify(
              original_challenge,
              allowed_credentials: allowed_credentials,
            )
          ).to be_truthy
        end
      end

      context "and it's equal to the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 5) }

        it "doesn't verify" do
          expect {
            assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
          }.to raise_exception(WebAuthn::SignCountVerificationError)
        end
      end

      context "and it's less than the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 4) }

        it "doesn't verify" do
          expect {
            assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
          }.to raise_exception(WebAuthn::SignCountVerificationError)
        end
      end
    end
  end

  describe "migrated U2F credential" do
    let(:origin) { "https://f69df4d9.ngrok.io" }
    let(:app_id) { "#{origin}/appid" }
    let(:migrated_credential) do
      WebAuthn::U2fMigrator.new(
        app_id: app_id,
        certificate: seeds[:u2f_migration][:stored_credential][:certificate],
        key_handle: seeds[:u2f_migration][:stored_credential][:key_handle],
        public_key: seeds[:u2f_migration][:stored_credential][:public_key],
        counter: 41
      )
    end
    let(:allowed_credentials) do
      [
        {
          id: migrated_credential.credential.id,
          public_key: migrated_credential.credential.public_key,
        }
      ]
    end

    let(:assertion_data) { seeds[:u2f_migration][:assertion] }
    let(:assertion_response) do
      WebAuthn::AuthenticatorAssertionResponse.new(
        credential_id: Base64.strict_decode64(assertion_data[:id]),
        client_data_json: Base64.strict_decode64(assertion_data[:response][:client_data_json]),
        authenticator_data: Base64.strict_decode64(assertion_data[:response][:authenticator_data]),
        signature: Base64.strict_decode64(assertion_data[:response][:signature])
      )
    end
    let(:original_challenge) { Base64.strict_decode64(assertion_data[:challenge]) }

    context "when correct FIDO AppID is given as rp_id" do
      it "verifies" do
        expect(
          assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials, rp_id: app_id)
        ).to be_truthy
      end

      it "is valid" do
        expect(
          assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials, rp_id: app_id)
        ).to be_truthy
      end
    end
  end

  context "when Authenticator Data is invalid" do
    let(:authenticator_data) { assertion[:response][:authenticator_data][0..31] }

    it "doesn't verify" do
      expect {
        assertion_response.verify(original_challenge, allowed_credentials: allowed_credentials)
      }.to raise_exception(WebAuthn::AuthenticatorDataVerificationError)
    end

    it "is invalid" do
      expect(assertion_response.valid?(original_challenge, allowed_credentials: allowed_credentials)).to be_falsy
    end
  end
end
