# frozen_string_literal: true

require "spec_helper"
require "webauthn/metadata/attributes"

RSpec.describe WebAuthn::Metadata::Attributes do
  subject do
    double = Class.new(Object)
    double.extend WebAuthn::Metadata::Attributes
    double
  end

  context ".json_accessor" do
    it "generates snake cased accessor methods for camel cased keys" do
      subject.public_send(:json_accessor, "fooBarBaz")

      expect(subject.new).to respond_to(:foo_bar_baz, :foo_bar_baz=)
    end

    it "keeps accessor methods snake cased if they already were so" do
      subject.public_send(:json_accessor, "snake_case")

      expect(subject.new).to respond_to(:snake_case, :snake_case=)
    end

    it "generates a setter method that sends 'coerce' to the specified class or module" do
      coercer = instance_spy("Coercer")
      subject.public_send(:json_accessor, "quxQuz", coercer)

      instance = subject.new
      instance.qux_quz = "testing"

      expect(coercer).to have_received(:coerce).with("testing")
    end
  end

  context ".from_json" do
    before(:each) { subject.public_send(:json_accessor, "fooBar") }

    it "sends messages to snake cased setter methods from camel case keyed hashes" do
      instance = subject.from_json("fooBar" => 123)

      expect(instance).to have_attributes(foo_bar: 123)
    end

    it "sends messages to snake cased setter methods from snake case keyed hashes" do
      instance = subject.from_json("foo_bar" => 123)

      expect(instance).to have_attributes(foo_bar: 123)
    end

    it "does not send messages if the instance does not respond to it" do
      subject.from_json("shouldBeSafe" => 123)
    end
  end
end
