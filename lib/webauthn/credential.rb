# frozen_string_literal: true

require "webauthn/public_key_credential/creation_options"
require "webauthn/public_key_credential/request_options"
require "webauthn/public_key_credential_with_assertion"
require "webauthn/public_key_credential_with_attestation"

module WebAuthn
  module Credential
    def self.options_for_create(**keyword_arguments)
      WebAuthn::PublicKeyCredential::CreationOptions.new(**keyword_arguments)
    end

    def self.options_for_get(**keyword_arguments)
      WebAuthn::PublicKeyCredential::RequestOptions.new(**keyword_arguments)
    end

    def self.from_create(credential)
      WebAuthn::PublicKeyCredentialWithAttestation.from_client(credential)
    end

    def self.from_get(credential)
      WebAuthn::PublicKeyCredentialWithAssertion.from_client(credential)
    end
  end
end
