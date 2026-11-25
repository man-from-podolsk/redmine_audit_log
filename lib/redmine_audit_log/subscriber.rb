# frozen_string_literal: true

module RedmineAuditLog
  # Listens to Rails' own "request started / request finished" events, so it sees every controller without
  # changing their before/after actions. Writes one entry per logged write request with the collected
  # model changes.
  module Subscriber
    module_function

    def install
      return if @installed

      @installed = true
      ActiveSupport::Notifications.subscribe('start_processing.action_controller') do |*args|
        start(ActiveSupport::Notifications::Event.new(*args).payload)
      end
      ActiveSupport::Notifications.subscribe('process_action.action_controller') do |*args|
        finish(ActiveSupport::Notifications::Event.new(*args).payload)
      end
    end

    def start(_payload)
      Current.in_request = true
      Current.changes = []
      Current.auth_logged = false
    rescue StandardError
      nil
    end

    def finish(payload)
      controller = payload[:controller].to_s.delete_suffix('Controller').underscore
      action = payload[:action].to_s
      request = payload[:request]
      kind = Classifier.classify(payload[:method], controller, action)
      changes = Array(Current.changes)

      return if kind == :skip
      return if kind == :routine && !Config.log_routine? && changes.none? { |c| c['event'] == 'destroy' }

      status = payload[:status] || (payload[:exception] ? 500 : nil)
      user = User.current
      attrs = Recorder.request_attributes(request, user).merge(
        'category' => Classifier.category(controller),
        'event' => 'request',
        'controller_action' => "#{controller}##{action}",
        'status' => status,
        'params' => Sanitizer.params(payload[:params]),
        'changes_json' => changes.empty? ? nil : Sanitizer.to_json(changes),
        'auth_method' => Recorder.api_request?(request) ? 'API' : nil,
        'message' => payload[:exception]&.first
      )
      attrs['alert'] = Alerts.request_alert?(user, controller, action, payload[:params], changes)
      Recorder.write(attrs)
    rescue StandardError => e
      Rails.logger&.error("Audit Log: request not logged: #{e.class}: #{e.message}")
    ensure
      Current.in_request = false
      Current.changes = []
    end
  end
end
