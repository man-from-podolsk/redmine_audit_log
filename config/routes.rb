# frozen_string_literal: true

# The address comes from config/audit_log.yml (mount_path), read when Redmine starts.
# Nothing links to it; for anyone but the auditors it answers "page not found".
audit_log_base = RedmineAuditLog::Config.mount_path

get  "#{audit_log_base}", to: 'audit_log#index', as: 'audit_log', defaults: { format: 'html' }
get  "#{audit_log_base}.csv", to: 'audit_log#index', as: 'audit_log_csv', defaults: { format: 'csv' }
get  "#{audit_log_base}/unlock", to: 'audit_log#unlock', as: 'audit_log_unlock'
post "#{audit_log_base}/unlock", to: 'audit_log#verify_unlock'
post "#{audit_log_base}/verify", to: 'audit_log#verify_chain', as: 'audit_log_verify'
post "#{audit_log_base}/lock", to: 'audit_log#lock', as: 'audit_log_lock'
