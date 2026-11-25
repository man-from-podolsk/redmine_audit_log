# frozen_string_literal: true

module RedmineAuditLog
  # Collects "before -> after" of administrative records during a web request. The collected changes are
  # written together with the request entry (Subscriber). Changes outside web requests (console, rake)
  # are not collected.
  module ModelTracking
    # Full tracking: create, update, destroy
    FULL = %w[
      Setting Principal Member MemberRole Role Tracker IssueStatus CustomField AuthSource Project
      EnabledModule Version IssueCategory Enumeration EmailAddress Repository WorkflowRule Query
    ].freeze
    # Deletions only: their creation and editing is visible in Activity
    DESTROY_ONLY = %w[Issue Attachment WikiPage TimeEntry Journal News Message Document].freeze

    module_function

    def install
      FULL.each { |name| attach(name, %i[create update destroy]) }
      DESTROY_ONLY.each { |name| attach(name, %i[destroy]) }
    end

    def attach(name, events)
      klass = name.safe_constantize
      return unless klass && klass < ActiveRecord::Base
      return if klass.instance_variable_get(:@redmine_audit_log_tracked)

      klass.instance_variable_set(:@redmine_audit_log_tracked, true)
      klass.after_create { |record| ModelTracking.record(record, 'create') } if events.include?(:create)
      klass.after_update { |record| ModelTracking.record(record, 'update') } if events.include?(:update)
      klass.after_destroy { |record| ModelTracking.record(record, 'destroy') } if events.include?(:destroy)
    end

    def record(record, event)
      return unless Current.in_request

      changes =
        case event
        when 'destroy' then {}
        else Sanitizer.changes(record.class.name, record.saved_changes,
                               setting_name: record.respond_to?(:name) ? record.name : nil)
        end
      return if event == 'update' && changes.empty?

      Current.record_change(
        'model' => record.class.name,
        'id' => record.id,
        'label' => label(record),
        'event' => event,
        'changes' => changes
      )
    rescue StandardError => e
      Rails.logger&.error("Audit Log: could not track #{record.class.name}##{record.id}: #{e.message}")
    end

    def label(record)
      text =
        if record.is_a?(Setting) then record.name
        elsif record.respond_to?(:login) && record.login.present? then record.login
        else record.to_s
        end
      Sanitizer.short(text.to_s)[0, 120]
    rescue StandardError
      nil
    end
  end
end
