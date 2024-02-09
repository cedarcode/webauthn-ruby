# frozen_string_literal: true

require "bundler/setup"
require "webauthn"
require "cbor"

require "byebug"
require "webauthn/fake_client"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  config.after do
    WebAuthn.instance_variable_set(:@configuration, nil)
  end
end

def create_credential(
  client: WebAuthn::FakeClient.new,
  rp_id: nil,
  relying_party: WebAuthn.configuration.relying_party
)
  rp_id ||= relying_party.id || URI.parse(client.origin).host

  create_result = client.create(rp_id: rp_id)

  attestation_object =
    if client.encoding
      relying_party.encoder.decode(create_result["response"]["attestationObject"])
    else
      create_result["response"]["attestationObject"]
    end

  client_data_json =
    if client.encoding
      relying_party.encoder.decode(create_result["response"]["clientDataJSON"])
    else
      create_result["response"]["clientDataJSON"]
    end

  response =
    WebAuthn::AuthenticatorAttestationResponse
    .new(
      attestation_object: attestation_object,
      client_data_json: client_data_json,
      relying_party: relying_party
    )

  credential_public_key = response.credential.public_key

  [create_result["id"], credential_public_key, response.authenticator_data.sign_count]
end

def fake_origin
  "http://localhost"
end

def fake_challenge
  SecureRandom.random_bytes(32)
end

def fake_cose_credential_key(algorithm: -7, x_coordinate: nil, y_coordinate: nil)
  crv_p256 = 1

  COSE::Key::EC2.new(
    alg: algorithm,
    crv: crv_p256,
    x: x_coordinate || SecureRandom.random_bytes(32),
    y: y_coordinate || SecureRandom.random_bytes(32)
  ).serialize
end

def key_bytes(public_key)
  public_key.to_bn.to_s(2)
end

# Borrowed from activesupport
def silence_warnings
  old_verbose, $VERBOSE = $VERBOSE, nil
  yield
ensure
  $VERBOSE = old_verbose
end

class RootCertificateFinder
  def initialize(certificate, return_empty)
    @certificate = certificate
    @return_empty = return_empty
  end

  def find(*)
    if @return_empty
      []
    elsif @certificate.is_a?(OpenSSL::X509::Certificate)
      [@certificate]
    else
      certificate_path = File.expand_path(
        File.join(__dir__, 'support', 'roots', @certificate)
      )
      [OpenSSL::X509::Certificate.new(File.read(certificate_path))]
    end
  end
end

def finder_for(certificate_file, return_empty: false)
  RootCertificateFinder.new(certificate_file, return_empty)
end

def create_rsa_key
  key_bits = 1024 # NOTE: Use 2048 or more in real life! We use 1024 here just for making the test fast.

  OpenSSL::PKey::RSA.new(key_bits)
end

def create_ec_key
  OpenSSL::PKey::EC.generate("prime256v1")
end

X509_V3 = 2

def create_root_certificate(key, not_before: Time.now - 1, not_after: Time.now + 60)
  certificate = OpenSSL::X509::Certificate.new

  certificate.version = X509_V3
  certificate.subject = OpenSSL::X509::Name.parse("CN=Root-#{rand(1_000_000)}")
  certificate.issuer = certificate.subject
  certificate.public_key = key
  certificate.not_before = not_before
  certificate.not_after = not_after

  extension_factory = OpenSSL::X509::ExtensionFactory.new
  extension_factory.subject_certificate = certificate
  extension_factory.issuer_certificate = certificate

  certificate.extensions = [
    extension_factory.create_extension("basicConstraints", "CA:TRUE", true),
    extension_factory.create_extension("keyUsage", "keyCertSign,cRLSign", true),
  ]

  certificate.sign(key, "SHA256")

  certificate
end

def issue_certificate(
  ca_certificate,
  ca_key,
  key,
  version: X509_V3,
  name: "CN=Cert-#{rand(1_000_000)}",
  not_before: Time.now - 1,
  not_after: Time.now + 60,
  extensions: nil
)
  certificate = OpenSSL::X509::Certificate.new

  certificate.version = version
  certificate.subject = OpenSSL::X509::Name.parse(name)
  certificate.issuer = ca_certificate.subject
  certificate.not_before = not_before
  certificate.not_after = not_after
  certificate.public_key = key

  if extensions
    certificate.extensions = extensions
  end

  certificate.sign(ca_key, "SHA256")

  certificate
end

def fake_certificate_chain_validation_time(attestation_statement, time)
  allow(attestation_statement).to receive(:attestation_root_certificates_store)
    .and_wrap_original do |m, *_args, **kwargs|
    store = m.call(**kwargs)
    store.time = time
    store
  end
end

def base64_strict_encode64(data)
  [data].pack("m0")
end

def base64_strict_decode64(data)
  data.unpack1("m0")
end

def base64_urlsafe_decode64(data)
  if !data.end_with?("=") && data.length % 4 != 0
    data = data.ljust((data.length + 3) & ~3, "=")
    data.tr!("-_", "+/")
  else
    data = data.tr("-_", "+/")
  end
  data.unpack1("m0")
end

def base64_urlsafe_encode64(data)
  str = base64_strict_encode64(data)
  str.tr!("+/", "-_")
  str
end
