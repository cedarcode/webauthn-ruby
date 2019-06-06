# frozen_string_literal: true

require "cose/key"

# TODO: Move this to cose gem
module COSE
  # https://tools.ietf.org/html/rfc8152#section-8.1
  Algorithm = Struct.new(:id, :name, :hash, :kty, :key_curve) do
    @registered = {}

    def self.register(id, name, hash, kty, key_curve = nil)
      @registered[id] = COSE::Algorithm.new(id, name, hash, kty, key_curve)
    end

    def self.find(id)
      @registered[id]
    end

    def self.by_name(name)
      @registered.values.detect { |algorithm| algorithm.name == name }
    end

    def value
      id
    end
  end
end

COSE::Algorithm.register(-7, "ES256", "SHA256", COSE::Key::EC2::KTY_EC2, "prime256v1")
COSE::Algorithm.register(-35, "ES384", "SHA384", COSE::Key::EC2::KTY_EC2, "prime256v1")
COSE::Algorithm.register(-36, "ES512", "SHA512", COSE::Key::EC2::KTY_EC2, "prime256v1")
COSE::Algorithm.register(-37, "PS256", "SHA256", COSE::Key::RSA::KTY_RSA)
COSE::Algorithm.register(-38, "PS384", "SHA384", COSE::Key::RSA::KTY_RSA)
COSE::Algorithm.register(-39, "PS512", "SHA512", COSE::Key::RSA::KTY_RSA)
COSE::Algorithm.register(-257, "RS256", "SHA256", COSE::Key::RSA::KTY_RSA)
COSE::Algorithm.register(-258, "RS384", "SHA384", COSE::Key::RSA::KTY_RSA)
COSE::Algorithm.register(-259, "RS512", "SHA512", COSE::Key::RSA::KTY_RSA)
COSE::Algorithm.register(-65535, "RS1", "SHA1", COSE::Key::RSA::KTY_RSA)
