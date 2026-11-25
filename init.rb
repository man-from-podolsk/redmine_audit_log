# frozen_string_literal: true

# Audit Log: who signed in, who failed to, and what was changed in Redmine settings, users, roles,
# projects and the like, with "before -> after". The journal is reachable only at the address from
# config/audit_log.yml, only for the logins listed there, and only after entering one's own password and
# the journal password. Settings live in that file, not in the database, so Redmine administrators
# cannot see or change them. See README.md.

Redmine::Plugin.register :redmine_audit_log do
  name 'Audit Log'
  author 'man-from-podolsk'
  description 'Sign-in and administrative change journal, hidden from Redmine administrators.'
  version '1.0.0'
  url 'https://github.com/man-from-podolsk/redmine_audit_log'
  requires_redmine version_or_higher: '6.0.0'
end

AccountController.prepend(RedmineAuditLog::AccountControllerPatch) unless AccountController < RedmineAuditLog::AccountControllerPatch
ApplicationController.prepend(RedmineAuditLog::ApplicationControllerPatch) unless ApplicationController < RedmineAuditLog::ApplicationControllerPatch
RedmineAuditLog::ModelTracking.install
RedmineAuditLog::Subscriber.install
