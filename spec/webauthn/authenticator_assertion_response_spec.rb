# frozen_string_literal: true

require "spec_helper"
require "support/seeds"
require "webauthn/attestation_statement/fido_u2f/public_key"
require "webauthn/authenticator_assertion_response"
require "webauthn/u2f_migrator"

RSpec.describe WebAuthn::AuthenticatorAssertionResponse do
  let(:client) { WebAuthn::FakeClient.new(actual_origin, encoding: false) }

  let!(:credential) { create_credential(client: client) }
  let(:credential_public_key) { credential[1] }

  let(:origin) { fake_origin }
  let(:actual_origin) { origin }
  let(:original_challenge) { fake_challenge }
  let(:assertion) { client.get(challenge: original_challenge) }
  let(:authenticator_data) { assertion["response"]["authenticatorData"] }

  let(:assertion_response) do
    WebAuthn::AuthenticatorAssertionResponse.new(
      client_data_json: assertion["response"]["clientDataJSON"],
      authenticator_data: authenticator_data,
      signature: assertion["response"]["signature"]
    )
  end

  let(:challenge) { original_challenge }
  let(:public_key) { credential_public_key }
  let(:sign_count) { 0 }
  let(:user_presence) { nil }
  let(:user_verification) { nil }
  let(:rp_id) { nil }

  before do
    WebAuthn.configuration.allowed_origins = [origin]
  end

  shared_examples "a valid assertion response" do
    it "verifies" do
      expect(
        assertion_response.verify(
          challenge,
          public_key: public_key,
          sign_count: sign_count,
          user_presence: user_presence,
          user_verification: user_verification,
          rp_id: rp_id
        )
      ).to be_truthy
    end

    it "is valid" do
      expect(
        assertion_response.valid?(
          challenge,
          public_key: public_key,
          sign_count: sign_count,
          user_presence: user_presence,
          user_verification: user_verification,
          rp_id: rp_id
        )
      ).to be_truthy
    end
  end

  shared_examples "an invalid assertion response that raises" do |expected_error|
    it "doesn't verify" do
      expect {
        assertion_response.verify(
          challenge,
          public_key: public_key,
          sign_count: sign_count,
          user_presence: user_presence,
          user_verification: user_verification,
          rp_id: rp_id
        )
      }.to raise_error(expected_error)
    end

    it "is invalid" do
      expect(
        assertion_response.valid?(
          challenge,
          public_key: public_key,
          sign_count: sign_count,
          user_presence: user_presence,
          user_verification: user_verification,
          rp_id: rp_id
        )
      ).to be_falsy
    end
  end

  context "when everything's in place" do
    it_behaves_like "a valid assertion response"
  end

  # Gem version v1.11.0 and lower, used to behave so that Credential#public_key
  # returned an EC P-256 uncompressed point.
  #
  # Because of https://github.com/cedarcode/webauthn-ruby/issues/137 this was changed
  # and Credential#public_key started returning the unchanged COSE_Key formatted
  # credentialPublicKey (as in https://www.w3.org/TR/webauthn/#credentialpublickey).
  #
  # Given that the credential public key is expected to be stored long-term by the gem
  # user and later be passed as the public_key argument in the
  # AuthenticatorAssertionResponse.verify call, we then need to support the two formats.
  context "when everything's in place with the old public key format" do
    let(:public_key) {
      WebAuthn::AttestationStatement::FidoU2f::PublicKey
        .new(credential_public_key)
        .to_uncompressed_point
    }

    it_behaves_like "a valid assertion response"
  end

  context "if signature was signed with a different key" do
    let(:public_key) do
      _different_id, different_public_key = create_credential(client: client)
      different_public_key
    end

    it_behaves_like "an invalid assertion response that raises", WebAuthn::SignatureVerificationError
  end

  describe "type validation" do
    context "if type is create instead of get" do
      before do
        allow(client).to receive(:type_for).and_return("webauthn.create")
      end

      it_behaves_like "an invalid assertion response that raises", WebAuthn::TypeVerificationError
    end
  end

  describe "user present validation" do
    context "when user presence flag is off" do
      let(:assertion) { client.get(challenge: original_challenge, user_present: false, user_verified: false) }

      context "when silent_authentication is not set" do
        context 'when user presence is not set' do
          it_behaves_like "an invalid assertion response that raises", WebAuthn::UserPresenceVerificationError
        end

        context 'when user presence is not required' do
          let(:user_presence) { false }

          it_behaves_like "a valid assertion response"
        end

        context 'when user presence is required' do
          let(:user_presence) { true }

          it_behaves_like "an invalid assertion response that raises", WebAuthn::UserPresenceVerificationError
        end
      end

      context "when silent_authentication is disabled" do
        around do |ex|
          old_value = WebAuthn.configuration.silent_authentication
          WebAuthn.configuration.silent_authentication = false

          ex.run

          WebAuthn.configuration.silent_authentication = old_value
        end

        context 'when user presence is not set' do
          it_behaves_like "an invalid assertion response that raises", WebAuthn::UserPresenceVerificationError
        end

        context 'when user presence is not required' do
          let(:user_presence) { false }

          it_behaves_like "a valid assertion response"
        end

        context 'when user presence is required' do
          let(:user_presence) { true }

          it_behaves_like "an invalid assertion response that raises", WebAuthn::UserPresenceVerificationError
        end
      end

      context "when silent_authentication is enabled" do
        around do |ex|
          old_value = WebAuthn.configuration.silent_authentication
          WebAuthn.configuration.silent_authentication = true

          ex.run

          WebAuthn.configuration.silent_authentication = old_value
        end

        context 'when user presence is not set' do
          it_behaves_like "a valid assertion response"
        end

        context 'when user presence is not required' do
          let(:user_presence) { false }

          it_behaves_like "a valid assertion response"
        end

        context 'when user presence is required' do
          let(:user_presence) { true }

          it_behaves_like "an invalid assertion response that raises", WebAuthn::UserPresenceVerificationError
        end
      end
    end
  end

  describe "user verified validation" do
    context "if user flags are off" do
      let(:assertion) { client.get(challenge: original_challenge, user_present: true, user_verified: false) }
      let(:user_verification) { true }

      it_behaves_like "an invalid assertion response that raises", WebAuthn::UserVerifiedVerificationError
    end
  end

  describe "challenge validation" do
    context "if challenge doesn't match" do
      let(:challenge) { fake_challenge }

      it_behaves_like "an invalid assertion response that raises", WebAuthn::ChallengeVerificationError
    end
  end

  describe "origin validation" do
    context "if origin doesn't match" do
      let(:actual_origin) { "http://different-origin" }

      it_behaves_like "an invalid assertion response that raises", WebAuthn::OriginVerificationError
    end
  end

  describe "tokenBinding validation" do
    let(:client) { WebAuthn::FakeClient.new(actual_origin, token_binding: token_binding, encoding: false) }

    context "it has stuff" do
      let(:token_binding) { { status: "supported" } }

      it_behaves_like "a valid assertion response"
    end

    context "has an invalid format" do
      let(:token_binding) { "invalid token binding format" }

      it_behaves_like "an invalid assertion response that raises", WebAuthn::TokenBindingVerificationError
    end
  end

  describe "rp_id validation" do
    before do
      WebAuthn.configuration.rp_id = "different-rp_id"
    end

    context "if rp_id_hash doesn't match" do
      it_behaves_like "an invalid assertion response that raises", WebAuthn::RpIdVerificationError
    end

    context "when correct rp_id is explicitly given" do
      let(:rp_id) { URI.parse(origin).host }

      it_behaves_like "a valid assertion response"
    end
  end

  describe "sign_count validation" do
    context "if authenticator does not support counter" do
      let(:assertion) { client.get(challenge: original_challenge, sign_count: 0) }

      it_behaves_like "a valid assertion response"
    end

    context "when the authenticator supports counter" do
      context "and it's greater than the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 6) }
        let(:sign_count) { 5 }

        it_behaves_like "a valid assertion response"
      end

      context "and it's equal to the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 5) }
        let(:sign_count) { 5 }

        it_behaves_like "an invalid assertion response that raises", WebAuthn::SignCountVerificationError
      end

      context "and it's less than the stored counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: 4) }
        let(:sign_count) { 5 }

        it_behaves_like "an invalid assertion response that raises", WebAuthn::SignCountVerificationError
      end

      context "when the RP opts out of verifying the signature counter" do
        let(:assertion) { client.get(challenge: original_challenge, sign_count: false) }
        let(:sign_count) { 5 }

        it_behaves_like "an invalid assertion response that raises", WebAuthn::SignCountVerificationError
      end
    end
  end

  describe "top_origin validation" do
    let(:client) { WebAuthn::FakeClient.new(origin, encoding: false, cross_origin: cross_origin, top_origin: client_top_origin) }
    let(:top_origin) { fake_top_origin }

    before do
      WebAuthn.configuration.allowed_top_origins = allowed_top_origins
      WebAuthn.configuration.verify_cross_origin = verify_cross_origin
    end

    context "when verify_cross_origin is false" do
      let(:verify_cross_origin) { false }

      context "when allowed_top_origins is not set" do
        let(:allowed_top_origins) { nil }

        context "when cross_origin is true" do
          let(:cross_origin) { true }

          context "when top_origin is set" do
            let(:client_top_origin) { top_origin }

            it_behaves_like "a valid assertion response"
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "a valid assertion response"
          end
        end

        context "when cross_origin is false" do
          let(:cross_origin) { false }

          context "when top_origin is set" do
            let(:client_top_origin) { top_origin }

            it_behaves_like "a valid assertion response"
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "a valid assertion response"
          end
        end

        context "when cross_origin is not set" do
          let(:cross_origin) { nil }

          context "when top_origin is set" do
            let(:client_top_origin) { top_origin }

            it_behaves_like "a valid assertion response"
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "a valid assertion response"
          end
        end
      end

      context "when allowed_top_origins is set" do
        let(:allowed_top_origins) { [top_origin] }

        context "when cross_origin is true" do
          let(:cross_origin) { true }

          context "when top_origin is set" do
            context "when top_origin matches client top_origin" do
              let(:client_top_origin) { top_origin }

              it_behaves_like "a valid assertion response"
            end

            context "when top_origin does not match client top_origin" do
              let(:client_top_origin) { "https://malicious.example.com" }

              it_behaves_like "a valid assertion response"
            end
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "a valid assertion response"
          end
        end

        context "when cross_origin is false" do
          let(:cross_origin) { false }

          context "when top_origin is set" do
            context "when top_origin matches client top_origin" do
              let(:client_top_origin) { top_origin }

              it_behaves_like "a valid assertion response"
            end

            context "when top_origin does not match client top_origin" do
              let(:client_top_origin) { "https://malicious.example.com" }

              it_behaves_like "a valid assertion response"
            end

            context "when top_origin is not set" do
              let(:client_top_origin) { nil }

              it_behaves_like "a valid assertion response"
            end
          end
        end

        context "when cross_origin is not set" do
          let(:cross_origin) { nil }

          context "when top_origin is set" do
            context "when top_origin matches client top_origin" do
              let(:client_top_origin) { top_origin }

              it_behaves_like "a valid assertion response"
            end

            context "when top_origin does not match client top_origin" do
              let(:client_top_origin) { "https://malicious.example.com" }

              it_behaves_like "a valid assertion response"
            end

            context "when top_origin is not set" do
              let(:client_top_origin) { nil }

              it_behaves_like "a valid assertion response"
            end
          end
        end
      end
    end

    context "when verify_cross_origin is true" do
      let(:verify_cross_origin) { true }

      context "when allowed_top_origins is not set" do
        let(:allowed_top_origins) { nil }

        context "when cross_origin is true" do
          let(:cross_origin) { true }

          context "when top_origin is set" do
            let(:client_top_origin) { top_origin }

            it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
          end
        end

        context "when cross_origin is false" do
          let(:cross_origin) { false }

          context "when top_origin is set" do
            let(:client_top_origin) { top_origin }

            it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "a valid assertion response"
          end
        end

        context "when cross_origin is not set" do
          let(:cross_origin) { nil }

          context "when top_origin is set" do
            let(:client_top_origin) { top_origin }

            it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "a valid assertion response"
          end
        end
      end

      context "when allowed_top_origins is set" do
        let(:allowed_top_origins) { [top_origin] }

        context "when cross_origin is true" do
          let(:cross_origin) { true }

          context "when top_origin is set" do
            context "when top_origin matches client top_origin" do
              let(:client_top_origin) { top_origin }

              it_behaves_like "a valid assertion response"
            end

            context "when top_origin does not match client top_origin" do
              let(:client_top_origin) { "https://malicious.example.com" }

              it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
            end
          end

          context "when top_origin is not set" do
            let(:client_top_origin) { nil }

            it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
          end
        end

        context "when cross_origin is false" do
          let(:cross_origin) { false }

          context "when top_origin is set" do
            context "when top_origin matches client top_origin" do
              let(:client_top_origin) { top_origin }

              it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
            end

            context "when top_origin does not match client top_origin" do
              let(:client_top_origin) { "https://malicious.example.com" }

              it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
            end

            context "when top_origin is not set" do
              let(:client_top_origin) { nil }

              it_behaves_like "a valid assertion response"
            end
          end
        end

        context "when cross_origin is not set" do
          let(:cross_origin) { nil }

          context "when top_origin is set" do
            context "when top_origin matches client top_origin" do
              let(:client_top_origin) { top_origin }

              it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
            end

            context "when top_origin does not match client top_origin" do
              let(:client_top_origin) { "https://malicious.example.com" }

              it_behaves_like "an invalid assertion response that raises", WebAuthn::TopOriginVerificationError
            end

            context "when top_origin is not set" do
              let(:client_top_origin) { nil }

              it_behaves_like "a valid assertion response"
            end
          end
        end
      end
    end
  end

  describe "migrated U2F credential" do
    let(:origin) { "https://example.org" }
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
    let(:credential_public_key) { migrated_credential.credential.public_key }

    let(:assertion_data) { seeds[:u2f_migration][:assertion] }
    let(:assertion_response) do
      WebAuthn::AuthenticatorAssertionResponse.new(
        client_data_json: WebAuthn::Encoders::Base64Encoder.decode(assertion_data[:response][:client_data_json]),
        authenticator_data: WebAuthn::Encoders::Base64Encoder.decode(assertion_data[:response][:authenticator_data]),
        signature: WebAuthn::Encoders::Base64Encoder.decode(assertion_data[:response][:signature])
      )
    end
    let(:original_challenge) { WebAuthn::Encoders::Base64Encoder.decode(assertion_data[:challenge]) }

    context "when correct FIDO AppID is given as rp_id" do
      let(:rp_id) { app_id }

      it_behaves_like "a valid assertion response"
    end
  end

  context "when Authenticator Data is invalid" do
    let(:authenticator_data) { assertion["response"]["authenticatorData"][0..31] }

    it_behaves_like "an invalid assertion response that raises", WebAuthn::AuthenticatorDataVerificationError
  end
end
