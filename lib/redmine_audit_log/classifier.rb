# frozen_string_literal: true

module RedmineAuditLog
  # Decides which write requests go into the journal.
  module Classifier
    WRITE_METHODS = %w[POST PUT PATCH DELETE].freeze

    # Logged separately (login, logout, 2FA) or by the journal itself
    HANDLED = {
      'account' => %w[login logout twofa twofa_resend],
      'audit_log' => :all
    }.freeze

    # Pure noise: previews, uploads before saving, layout of My page, sudo mode prompts
    NOISE = {
      'previews' => :all,
      'attachments' => %w[upload],
      'my' => %w[update_page add_block remove_block order_blocks],
      'auto_completes' => :all,
      'context_menus' => :all
    }.freeze

    # Changes that are already visible in Activity, issue history or wiki history.
    # Logged only with log_routine: true. Deletions are never routine.
    ROUTINE = {
      'issues' => %w[create update bulk_update],
      'journals' => %w[new edit update],
      'watchers' => :all,
      'wiki' => %w[edit update add_attachment preview],
      'messages' => %w[new edit reply quote],
      'news' => %w[new create edit update],
      'comments' => %w[create],
      'timelog' => %w[new create edit update bulk_update],
      'documents' => %w[new create edit update add_attachment],
      'files' => %w[new create],
      'issue_relations' => %w[create],
      'reactions' => :all
    }.freeze

    module_function

    def match?(table, controller, action)
      actions = table[controller.to_s]
      actions == :all || (actions.is_a?(Array) && actions.include?(action.to_s))
    end

    # :skip, :routine or :log
    def classify(http_method, controller, action)
      return :skip unless WRITE_METHODS.include?(http_method.to_s.upcase)
      return :skip if match?(HANDLED, controller, action) || match?(NOISE, controller, action)
      return :routine if match?(ROUTINE, controller, action)

      :log
    end

    # Short category for the journal: auth-related account actions or other changes
    def category(controller)
      controller.to_s == 'account' ? 'auth' : 'change'
    end
  end
end
