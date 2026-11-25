# frozen_string_literal: true

module RedmineAuditLog
  # Writes entries with the hash chain. Never raises: a journal problem must not break Redmine,
  # it goes to production.log instead.
  module Recorder
    ADVISORY_LOCK = 7_314_420_251

    module_function

    def write(attributes)
      attrs = normalize(attributes)
      AuditLogEntry.transaction do
        lock!
        prev = AuditLogEntry.order(id: :desc).limit(1).pick(:entry_hash)
        created_at = Time.now.utc.change(usec: 0)
        AuditLogEntry.create!(attrs.merge('created_at' => created_at, 'prev_hash' => prev,
                                          'entry_hash' => Chain.digest(attrs, prev, created_at)))
      end
      purge_daily
      true
    rescue StandardError => e
      Rails.logger&.error("Audit Log: could not write entry #{attributes[:event] || attributes['event']}: " \
                          "#{e.class}: #{e.message}")
      false
    end

    # Entries of one request: who, from where, with which browser
    def request_attributes(request, user = User.current)
      logged = user.respond_to?(:logged?) && user.logged?
      {
        'user_id' => logged ? user.id : nil,
        'user_login' => logged ? user.login : nil,
        'ip' => request&.remote_ip,
        'user_agent' => request&.user_agent,
        'http_method' => request&.request_method,
        'path' => request&.fullpath
      }
    end

    def auth_method(user)
      return nil unless user.respond_to?(:auth_source)

      source = user.auth_source
      source ? "#{source.auth_method_name}: #{source.name}" : 'local'
    rescue StandardError
      nil
    end

    def api_request?(request)
      return false unless request

      request.format&.json? || request.format&.xml? ||
        request.headers['X-Redmine-API-Key'].present? || request.params['key'].present?
    rescue StandardError
      false
    end

    def normalize(attributes)
      attrs = attributes.transform_keys(&:to_s)
      limits = { 'category' => 20, 'event' => 50, 'user_login' => 255, 'auth_method' => 100, 'ip' => 64,
                 'user_agent' => 255, 'http_method' => 10, 'controller_action' => 100, 'path' => 512,
                 'message' => 255 }
      limits.each { |key, limit| attrs[key] = Sanitizer.truncate(attrs[key], limit) if attrs.key?(key) }
      attrs.each { |key, value| attrs[key] = clean_string(value) if value.is_a?(String) }
      attrs['alert'] = attrs['alert'] ? true : false
      attrs.slice(*Chain::FIELDS)
    end

    # Invalid UTF-8 and NUL bytes are rejected by PostgreSQL
    def clean_string(value)
      value.dup.force_encoding(Encoding::UTF_8).scrub('?').delete("\u0000")
    end

    # PostgreSQL: one writer at a time, so the chain does not fork between Puma workers
    def lock!
      connection = AuditLogEntry.connection
      return unless connection.adapter_name.to_s.downcase.include?('postg')

      connection.execute("SELECT pg_advisory_xact_lock(#{ADVISORY_LOCK})")
    end

    def purge_daily
      @last_purge ||= nil
      return if @last_purge && @last_purge > 1.day.ago

      @last_purge = Time.now
      AuditLogEntry.purge!
    rescue StandardError => e
      Rails.logger&.error("Audit Log: purge failed: #{e.message}")
    end
  end
end
