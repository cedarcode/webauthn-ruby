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
  ALG_RSAPSS = 0x0016
  ALG_ECDSA = 0x0018
  ALG_ECC = 0x0023

  # ECC curves
  ECC_NIST_P256 = 0x0003

  # https://trustedcomputinggroup.org/resource/vendor-id-registry/ section 2 "TPM Capabilities Vendor ID (CAP_VID)"
  VENDOR_IDS = {
    "id:414D4400" => "AMD",
    "id:41544D4C" => "Atmel",
    "id:4252434D" => "Broadcom",
    "id:49424D00" => "IBM",
    "id:49465800" => "Infineon",
    "id:494E5443" => "Intel",
    "id:4C454E00" => "Lenovo",
    "id:4E534D20" => "National Semiconductor",
    "id:4E545A00" => "Nationz",
    "id:4E544300" => "Nuvoton Technology",
    "id:51434F4D" => "Qualcomm",
    "id:534D5343" => "SMSC",
    "id:53544D20" => "ST Microelectronics",
    "id:534D534E" => "Samsung",
    "id:534E5300" => "Sinosun",
    "id:54584E00" => "Texas Instruments",
    "id:57454300" => "Winbond",
    "id:524F4343" => "Fuzhou Rockchip",
  }.freeze
end
