# frozen_string_literal: true

module RedmineAuditLog
  # Prepended to AccountController (init.rb): records every sign-in attempt.
  # Works for local passwords and LDAP; attempts stopped by other plugins (e.g. redmine_login_attempts_limit)
  # are caught by the wrapper around #login and logged with the message the user saw.
  module AccountControllerPatch
    def login
      super
    ensure
      audit_log_login_fallback if request.post?
    end

    def twofa
      user = @user
      super
    ensure
      error = flash[:error].presence
      AuthLog.twofa_failure(request, user, error) if error && !Current.auth_logged
    end

    private

    def successful_authentication(user)
      AuthLog.login_success(request, user) unless Current.auth_logged
      super
    end

    def invalid_credentials
      AuthLog.login_failure(request, params[:username], 'invalid login or password') unless Current.auth_logged
      super
    end

    def account_locked(user, redirect_path = signin_path)
      AuthLog.login_failure(request, user&.login, 'account locked', user) unless Current.auth_logged
      super
    end

    def account_pending(user, redirect_path = signin_path)
      AuthLog.login_failure(request, user&.login, 'account not activated', user) unless Current.auth_logged
      super
    end

    def onthefly_creation_failed(user, auth_source_options = {})
      unless Current.auth_logged
        AuthLog.login_failure(request, user&.login, 'LDAP account needs registration (missing attributes)')
      end
      super
    end

    def audit_log_login_fallback
      return if Current.auth_logged
      return if params[:username].blank? && params[:password].blank?

      if session[:twofa_session_token].present?
        user = AuthLog.find_user(params[:username])
        AuthLog.twofa_pending(request, user)
      elsif User.current.anonymous?
        message = flash[:error].presence || flash.now[:error].presence || 'login refused'
        AuthLog.login_failure(request, params[:username], message.to_s)
      end
    rescue StandardError => e
      Rails.logger&.error("Audit Log: login fallback failed: #{e.message}")
    end
  end
end
