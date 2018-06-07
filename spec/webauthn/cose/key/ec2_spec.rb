# frozen_string_literal: true

require "webauthn/cose/key/ec2"

RSpec.describe WebAuthn::COSE::Key::EC2 do
  it "returns an error if crv is missing" do
    expect {
      WebAuthn::COSE::Key::EC2.new(curve: nil, x_coordinate: "x", y_coordinate: "y")
    }.to raise_error(ArgumentError, "Required curve is missing")
  end

  it "returns an error if x is missing" do
    expect {
      WebAuthn::COSE::Key::EC2.new(curve: 1, x_coordinate: nil, y_coordinate: "y")
    }.to raise_error(ArgumentError, "Required x-coordinate is missing")
  end

  it "returns an error if y is missing" do
    expect {
      WebAuthn::COSE::Key::EC2.new(curve: 1, x_coordinate: "x", y_coordinate: nil)
    }.to raise_error(ArgumentError, "Required y-coordinate is missing")
  end
end
