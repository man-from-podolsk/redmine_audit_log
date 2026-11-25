# frozen_string_literal: true

namespace :redmine do
  namespace :audit_log do
    desc 'Checks GitHub for a newer version of redmine_audit_log'
    task check_update: :environment do
      data = RedmineAuditLog::UpdateCheck.check!
      RedmineAuditLog::UpdateCheck.write_cache(data)
      if data['error']
        puts "Check failed: #{data['error']}"
        exit 1
      elsif RedmineAuditLog::UpdateCheck.update_available?(data)
        notice = RedmineAuditLog::UpdateCheck.notice(data)
        puts "Update available: #{notice[:installed]} -> #{notice[:latest] || "#{notice[:behind]} new commits"}"
        notice[:items].each { |item| puts "  - #{item}" }
        puts notice[:git] ? "git pull in plugins/#{notice[:folder]}" : "Archive: #{notice[:archive_url]}"
      else
        puts "Up to date (#{RedmineAuditLog::UpdateCheck.installed_version})"
      end
    end
  end
end
