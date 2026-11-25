# frozen_string_literal: true

module RedmineAuditLog
  # What is marked as an alert in the journal
  module Alerts
    USER_CONTROLLERS = %w[users groups principal_memberships email_addresses twofa twofa_backup_codes].freeze

    module_function

    # Someone changed an auditor's account (password, e-mail, login method, 2FA, status, rights...)
    # or the journal's own records were touched
    def request_alert?(actor, controller, action, params, changes)
      auditor_ids = auditor_ids()
      return false if auditor_ids.empty?

      touched = changes.select { |c| %w[User Principal AnonymousUser].include?(c['model']) || c['model'] == 'EmailAddress' }
                       .map { |c| c['model'] == 'EmailAddress' ? email_owner(c['id']) : c['id'] }
      if USER_CONTROLLERS.include?(controller)
        params = params.respond_to?(:to_h) ? params.to_h : {}
        touched << params['id'].to_i if controller == 'users' && params['id']
        touched << params['user_id'].to_i if params['user_id']
      end
      touched = touched.compact.map(&:to_i).uniq & auditor_ids
      touched.any? { |id| actor.nil? || actor.id != id }
    rescue StandardError
      false
    end

    def auditor_ids
      logins = Config.auditors
      return [] if logins.empty?

      User.where('LOWER(login) IN (?)', logins).pluck(:id)
    end

    def email_owner(email_id)
      EmailAddress.where(id: email_id).pick(:user_id)
    end
  end
end
