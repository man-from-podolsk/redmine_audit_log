# frozen_string_literal: true

module RedmineAuditLog
  # Login, 2FA and logout entries
  module AuthLog
    module_function

    def login_success(request, user)
      write(request, user, 'login_success', twofa_note(user))
    end

    # username: what was typed; user: the account if it exists
    def login_failure(request, username, reason, user = nil)
      user ||= find_user(username)
      write(request, user, 'login_failure', reason, typed_login: username)
    end

    def twofa_pending(request, user)
      write(request, user, 'login_twofa_pending', 'password accepted, waiting for 2FA code')
    end

    def twofa_failure(request, user, reason)
      write(request, user, 'login_twofa_failure', reason)
    end

    def logout(request, user, reason)
      write(request, user, reason == 'logout' ? 'logout' : 'session_end', reason)
    end

    def write(request, user, event, message, typed_login: nil)
      Current.auth_logged = true
      attrs = Recorder.request_attributes(request, User.anonymous).merge(
        'category' => 'auth',
        'event' => event,
        'user_id' => user&.id,
        'user_login' => user&.login || typed_login.to_s.strip.presence,
        'auth_method' => user ? Recorder.auth_method(user) : nil,
        'controller_action' => request ? "#{request.params['controller']}##{request.params['action']}" : nil,
        'message' => message
      )
      Recorder.write(attrs)
    rescue StandardError => e
      Rails.logger&.error("Audit Log: auth event #{event} not logged: #{e.message}")
    end

    def find_user(username)
      return nil if username.blank?

      User.find_by_login(username.to_s.strip)
    rescue StandardError
      nil
    end

    def twofa_note(user)
      user.respond_to?(:twofa_active?) && user.twofa_active? ? 'with 2FA' : nil
    end
  end
end
