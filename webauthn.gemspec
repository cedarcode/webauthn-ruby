# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "webauthn/version"

Gem::Specification.new do |spec|
  spec.name          = "webauthn"
  spec.version       = WebAuthn::VERSION
  spec.authors       = ["Gonzalo Rodriguez", "Braulio Martinez"]
  spec.email         = ["gonzalo@cedarcode.com", "braulio@cedarcode.com"]

  spec.summary       = "WebAuthn in ruby ― Ruby implementation of a WebAuthn Relying Party"
  spec.homepage      = "https://github.com/cedarcode/webauthn-ruby"
  spec.license       = "MIT"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/cedarcode/webauthn-ruby/issues",
    "changelog_uri" => "https://github.com/cedarcode/webauthn-ruby/blob/master/CHANGELOG.md",
    "source_code_uri" => "https://github.com/cedarcode/webauthn-ruby"
  }

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "cbor", "~> 0.5.9.2"
  spec.add_dependency "cose", "~> 0.1.0"
  spec.add_dependency "base64url", "~> 1.0.1"

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "byebug", "~> 10.0"
  spec.add_development_dependency "rake", "~> 12.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "rubocop", "0.57.0"
end
