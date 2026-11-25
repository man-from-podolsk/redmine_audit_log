# frozen_string_literal: true

module RedmineAuditLog
  # Prepended to ApplicationController (init.rb): logout and end of session
  module ApplicationControllerPatch
    private

    def logout_user
      user = User.current
      if user.respond_to?(:logged?) && user.logged?
        reason = controller_name == 'account' && action_name == 'logout' ? 'logout' : "session ended (#{controller_name}##{action_name})"
        AuthLog.logout(request, user, reason)
      end
      super
    end
  end
end
