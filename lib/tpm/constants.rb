# frozen_string_literal: true

module TPM
  # Section 6 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf

  GENERATED_VALUE = 0xFF544347

  ST_ATTEST_CERTIFY = 0x8017

  # Algorithms
  ALG_RSA = 0x0001
  ALG_SHA1 = 0x0004
  ALG_SHA256 = 0x000B
  ALG_NULL = 0x0010
  ALG_RSASSA = 0x0014
  ALG_ECDSA = 0x0018
  ALG_ECC = 0x0023

  # ECC curves
  ECC_NIST_P256 = 0x0003
end
