# frozen_string_literal: true

class CreateAuditLogEntries < ActiveRecord::Migration[7.2]
  def change
    create_table :audit_log_entries do |t|
      t.datetime :created_at, null: false
      t.string :category, limit: 20, null: false          # auth, change, access
      t.string :event, limit: 50, null: false             # login_success, login_failure, logout, request, ...
      t.boolean :alert, null: false, default: false
      t.integer :user_id
      t.string :user_login, limit: 255
      t.string :auth_method, limit: 100                   # local, LDAP: <name>, API key ...
      t.string :ip, limit: 64
      t.string :user_agent, limit: 255
      t.string :http_method, limit: 10
      t.string :controller_action, limit: 100
      t.string :path, limit: 512
      t.integer :status
      t.text :params
      t.text :changes_json
      t.string :message, limit: 255
      t.string :prev_hash, limit: 64
      t.string :entry_hash, limit: 64, null: false
    end
    add_index :audit_log_entries, :created_at
    add_index :audit_log_entries, [:user_id, :created_at]
    add_index :audit_log_entries, [:category, :created_at]
    add_index :audit_log_entries, [:alert, :created_at]
  end
end
