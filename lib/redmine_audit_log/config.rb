# frozen_string_literal: true

require 'yaml'

module RedmineAuditLog
  # Settings of the journal. They live in a file on the server, not in the database, so that Redmine
  # administrators cannot see or change them from the web:
  #
  #   /opt/redmine/config/audit_log.yml   owner root:www-data, mode 640
  #
  #   auditors: [ivanov, petrov]           Redmine logins allowed to open the journal
  #   password: "pbkdf2_sha256$..."        hash of the journal password (bin/audit_log_password)
  #   retention_days: 365                  older entries are deleted
  #   mount_path: "audit-log"              address of the journal: https://redmine/audit-log (restart to change)
  #   log_routine: false                   also log changes already visible in Activity (issues, comments...)
  #   unlock_minutes: 15                   how long the journal stays open after entering the passwords
  #
  # Without the file (or without auditors / password) the journal still records everything, but nobody
  # can open it.
  module Config
    DEFAULTS = {
      'auditors' => [],
      'password' => nil,
      'retention_days' => 365,
      'mount_path' => 'audit-log',
      'log_routine' => false,
      'unlock_minutes' => 15
    }.freeze

    module_function

    def path
      @path ||= File.join(Rails.root.to_s, 'config', 'audit_log.yml')
    end

    def path=(value)
      @path = value
      @cache = nil
    end

    # Re-read when the file changes, no restart needed (except mount_path)
    def all
      mtime = File.exist?(path) ? File.mtime(path) : nil
      return @cache[:data] if @cache && @cache[:mtime] == mtime

      data = DEFAULTS.dup
      if mtime
        loaded = YAML.safe_load(File.read(path)) || {}
        loaded = loaded['production'] if loaded.is_a?(Hash) && loaded['production'].is_a?(Hash)
        data = data.merge(loaded.transform_keys(&:to_s)) if loaded.is_a?(Hash)
      end
      @cache = { mtime: mtime, data: data }
      data
    rescue StandardError => e
      warn_once("Audit Log: cannot read #{path}: #{e.message}")
      DEFAULTS
    end

    def present?
      File.exist?(path)
    end

    def auditors
      Array(all['auditors']).map { |login| login.to_s.strip.downcase }.reject(&:empty?)
    end

    def auditor?(user)
      return false unless user.respond_to?(:login) && user.respond_to?(:logged?) && user.logged?

      auditors.include?(user.login.to_s.downcase)
    end

    def password_digest
      all['password'].to_s
    end

    def ready?
      auditors.any? && Password.valid_digest?(password_digest)
    end

    def retention_days
      days = all['retention_days'].to_i
      days.positive? ? days : 365
    end

    def mount_path
      value = all['mount_path'].to_s.strip.delete_prefix('/')
      value.match?(/\A[a-zA-Z0-9_-]{3,64}\z/) ? value : DEFAULTS['mount_path']
    end

    def log_routine?
      [true, 'true', 1, '1', 'yes'].include?(all['log_routine'])
    end

    def unlock_minutes
      minutes = all['unlock_minutes'].to_i
      minutes.between?(1, 240) ? minutes : 15
    end

    # Warning shown in the journal when the file is readable by everyone on the server
    def world_readable?
      present? && (File.stat(path).mode & 0o004) != 0
    end

    def warn_once(message)
      @warned ||= {}
      return if @warned[message]

      @warned[message] = true
      Rails.logger&.error(message)
    end
  end
end
