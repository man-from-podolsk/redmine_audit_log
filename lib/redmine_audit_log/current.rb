# frozen_string_literal: true

module RedmineAuditLog
  # Per-request state: model changes collected during the request and whether a login result was
  # already written. Reset by Rails between requests.
  class Current < ActiveSupport::CurrentAttributes
    attribute :changes, :auth_logged, :in_request

    def record_change(entry)
      return unless in_request

      self.changes ||= []
      changes << entry if changes.size < 200
    end
  end
end
