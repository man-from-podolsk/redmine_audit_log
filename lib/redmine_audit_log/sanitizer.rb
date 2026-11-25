# frozen_string_literal: true

require 'json'

module RedmineAuditLog
  # Removes secrets from request parameters and model changes and keeps them short.
  module Sanitizer
    FILTERED = '[FILTERED]'
    SECRET_KEY = /pass(word)?|secret|token|api_?key|\Akey\z|salt|twofa|otp|private_key|cookie|authenticity/i
    SECRET_ATTRIBUTES = %w[hashed_password salt twofa_totp_key twofa_totp_last_used_at account_password value_hash].freeze
    SKIP_PARAMS = %w[controller action format utf8 authenticity_token _method commit button].freeze
    # Attributes that change on their own and only add noise
    NOISE_ATTRIBUTES = %w[updated_on updated_at last_login_on lft rgt lock_version].freeze
    MAX_VALUE = 500
    MAX_JSON = 20_000

    module_function

    def secret_key?(key)
      key.to_s.match?(SECRET_KEY)
    end

    def params(hash)
      return nil unless hash.respond_to?(:to_h)

      clean = scrub(hash.to_h.except(*SKIP_PARAMS))
      clean.empty? ? nil : to_json(clean)
    end

    def scrub(value, key = nil)
      return FILTERED if key && secret_key?(key)

      case value
      when Hash
        value.each_with_object({}) { |(k, v), out| out[k.to_s] = scrub(v, k) }
      when Array
        value.first(50).map { |v| scrub(v) }
      when String
        value.length > MAX_VALUE ? "#{value[0, MAX_VALUE]}…" : value
      when Numeric, TrueClass, FalseClass, NilClass
        value
      else
        if value.respond_to?(:original_filename)
          "[file #{value.original_filename}]"
        else
          short(value.to_s)
        end
      end
    end

    # Changes of one record: { attribute => [before, after] }, secrets reduced to "changed"
    def changes(record_class, saved_changes, setting_name: nil)
      saved_changes.each_with_object({}) do |(attribute, (before, after)), out|
        next if NOISE_ATTRIBUTES.include?(attribute.to_s)

        secret = SECRET_ATTRIBUTES.include?(attribute.to_s) ||
                 (record_class == 'Setting' && attribute.to_s == 'value' && secret_key?(setting_name)) ||
                 (record_class == 'Token' && attribute.to_s == 'value')
        out[attribute.to_s] = secret ? [FILTERED, FILTERED] : [short(before), short(after)]
      end
    end

    def short(value)
      value = value.to_s if value.is_a?(Symbol)
      return value unless value.is_a?(String)

      value.length > MAX_VALUE ? "#{value[0, MAX_VALUE]}…" : value
    end

    def to_json(data)
      json = JSON.generate(data)
      json.length > MAX_JSON ? JSON.generate('truncated' => json[0, MAX_JSON]) : json
    end

    def truncate(value, limit)
      return nil if value.nil?

      value = value.to_s
      value.length > limit ? value[0, limit] : value
    end
  end
end
