# frozen_string_literal: true

# One record of the audit journal. Written only through RedmineAuditLog::Recorder; never edited.
class AuditLogEntry < ApplicationRecord
  CATEGORIES = %w[auth change access].freeze

  belongs_to :user, optional: true

  scope :newest_first, -> { order(id: :desc) }

  # Entries are only added; old ones are removed by purge! (delete_all, no callbacks)
  before_update { raise ActiveRecord::ReadOnlyRecord, 'audit log entries are read-only' }
  before_destroy { throw :abort }

  def changes_data
    parse(changes_json)
  end

  def params_data
    parse(params)
  end

  # Entries older than the retention period
  def self.purge!(days = RedmineAuditLog::Config.retention_days)
    where(arel_table[:created_at].lt(days.days.ago)).delete_all
  end

  private

  def parse(text)
    text.present? ? JSON.parse(text) : nil
  rescue JSON::ParserError
    text
  end
end
