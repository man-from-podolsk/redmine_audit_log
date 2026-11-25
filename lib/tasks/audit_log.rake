# frozen_string_literal: true

namespace :redmine do
  namespace :audit_log do
    desc 'Checks the hash chain of the audit journal and lists broken entries'
    task verify: :environment do
      broken = []
      count = 0
      previous = nil
      AuditLogEntry.order(:id).find_in_batches(batch_size: 2000) do |batch|
        batch = [previous] + batch if previous
        broken.concat(RedmineAuditLog::Chain.broken_ids(batch).reject { |id| previous && id == previous.id })
        count += batch.size - (previous ? 1 : 0)
        previous = batch.last
      end
      broken.uniq!
      puts "Checked: #{count}, broken: #{broken.size}"
      puts "Broken ids: #{broken.first(100).join(', ')}" if broken.any?
      exit(1) if broken.any?
    end

    desc 'Deletes entries older than retention_days from config/audit_log.yml'
    task purge: :environment do
      puts "Deleted: #{AuditLogEntry.purge!}"
    end
  end
end
