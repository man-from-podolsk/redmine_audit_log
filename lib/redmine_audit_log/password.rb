# frozen_string_literal: true

require 'base64'
require 'openssl'
require 'securerandom'

module RedmineAuditLog
  # The journal password: PBKDF2-HMAC-SHA256, stored as
  #   pbkdf2_sha256$<iterations>$<salt, base64>$<hash, base64>
  # The same format is produced by bin/audit_log_password and by the Python one-liner in the README,
  # so no Redmine or bundle is needed to make one.
  module Password
    PREFIX = 'pbkdf2_sha256'
    ITERATIONS = 600_000
    FORMAT = /\Apbkdf2_sha256\$(\d+)\$([A-Za-z0-9+\/=]+)\$([A-Za-z0-9+\/=]+)\z/

    module_function

    def create(clear, iterations: ITERATIONS)
      salt = SecureRandom.random_bytes(16)
      hash = derive(clear, salt, iterations, 32)
      [PREFIX, iterations, Base64.strict_encode64(salt), Base64.strict_encode64(hash)].join('$')
    end

    def valid_digest?(digest)
      match = FORMAT.match(digest.to_s)
      !match.nil? && match[1].to_i >= 100_000
    end

    def verify(clear, digest)
      match = FORMAT.match(digest.to_s)
      return false unless match && clear.is_a?(String) && !clear.empty?

      iterations = match[1].to_i
      return false if iterations < 100_000

      salt = Base64.strict_decode64(match[2])
      expected = Base64.strict_decode64(match[3])
      actual = derive(clear, salt, iterations, expected.bytesize)
      OpenSSL.fixed_length_secure_compare(actual, expected)
    rescue ArgumentError
      false
    end

    def derive(clear, salt, iterations, length)
      OpenSSL::KDF.pbkdf2_hmac(clear.to_s, salt: salt, iterations: iterations, length: length, hash: 'sha256')
    end
  end
end
