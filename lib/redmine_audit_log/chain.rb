# frozen_string_literal: true

require 'digest'
require 'json'

module RedmineAuditLog
  # Each entry stores the hash of the previous one and its own hash over its fields. Changing or deleting
  # an entry in the database breaks the chain, and the journal shows where. It does not prevent changes:
  # it makes them visible.
  module Chain
    FIELDS = %w[category event alert user_id user_login auth_method ip user_agent http_method
                controller_action path status params changes_json message].freeze

    module_function

    # A JSON array: every value is escaped, so no field can imitate the boundary between two others
    def input(attributes, prev_hash, created_at)
      values = FIELDS.map { |field| attributes[field].to_s }
      JSON.generate([prev_hash.to_s, created_at.to_i.to_s] + values)
    end

    def digest(attributes, prev_hash, created_at)
      Digest::SHA256.hexdigest(input(attributes, prev_hash, created_at))
    end

    # entries: each responds to #[] with the field names, #prev_hash, #entry_hash, #created_at, #id.
    # Returns the ids of entries that were changed or follow a gap. The first entry is trusted as the
    # start (older ones are deleted by retention).
    def broken_ids(entries)
      broken = []
      previous = nil
      entries.each do |entry|
        expected = digest(entry, entry.prev_hash, entry.created_at)
        linked = previous.nil? || entry.prev_hash == previous.entry_hash
        broken << entry.id unless expected == entry.entry_hash && linked
        previous = entry
      end
      broken
    end
  end
end
