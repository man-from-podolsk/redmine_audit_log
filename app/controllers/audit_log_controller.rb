# frozen_string_literal: true

# The journal. Reachable only at the address from config/audit_log.yml and only for the logins listed there;
# everyone else, administrators included, gets "page not found". Opening it needs the user's own Redmine
# password and the journal password. Every opening, export and failed attempt is itself logged.
class AuditLogController < ApplicationController
  PER_PAGE = 50
  MAX_FAILURES = 5
  FAILURE_WINDOW = 15.minutes
  SESSION_KEY = :audit_log_unlocked

  before_action :require_auditor
  before_action :require_unlocked, except: [:unlock, :verify_unlock]

  # GET
  def unlock
    @locked_out = locked_out?
    @password_missing = !RedmineAuditLog::Config.password_set?
  end

  # POST
  def verify_unlock
    unless RedmineAuditLog::Config.password_set?
      flash[:error] = l(:audit_log_error_password_not_set, path: RedmineAuditLog::Config.path)
      return redirect_to(audit_log_unlock_path)
    end
    if locked_out?
      access_log('unlock_refused', 'too many failed attempts', alert: true)
      flash[:error] = l(:audit_log_error_locked_out, minutes: (FAILURE_WINDOW / 60).to_i)
      return redirect_to(audit_log_unlock_path)
    end

    own_ok = User.current.check_password?(params[:own_password].to_s)
    journal_ok = RedmineAuditLog::Password.verify(params[:journal_password].to_s, RedmineAuditLog::Config.password_digest)
    if own_ok && journal_ok
      session[SESSION_KEY] = { 'user_id' => User.current.id,
                               'until' => RedmineAuditLog::Config.unlock_minutes.minutes.from_now.to_i }
      access_log('unlock', nil)
      redirect_to audit_log_path
    else
      failed = [('own password' unless own_ok), ('journal password' unless journal_ok)].compact.join(', ')
      access_log('unlock_failed', "wrong #{failed}", alert: true)
      flash[:error] = l(:audit_log_error_wrong_passwords)
      redirect_to audit_log_unlock_path
    end
  rescue AuthSourceException => e
    access_log('unlock_failed', "LDAP error: #{e.message}", alert: true)
    flash[:error] = e.message
    redirect_to audit_log_unlock_path
  end

  # GET
  def index
    scope = filtered_scope
    respond_to do |format|
      format.html do
        @entry_count = scope.count
        @entry_pages = Redmine::Pagination::Paginator.new(@entry_count, PER_PAGE, params['page'])
        @entries = scope.newest_first.limit(@entry_pages.per_page).offset(@entry_pages.offset).to_a
        @alerts_week = AuditLogEntry.where(alert: true).where(AuditLogEntry.arel_table[:created_at].gt(7.days.ago)).count
        @config = RedmineAuditLog::Config
        access_log('view', filters_summary) if params['page'].blank?
      end
      format.csv do
        access_log('export', filters_summary)
        send_data(csv(scope.newest_first.limit(100_000)), type: 'text/csv; header=present',
                                                          filename: "audit_log_#{Date.today.strftime('%Y%m%d')}.csv")
      end
    end
  end

  # POST
  def verify_chain
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
    access_log('verify', "#{count} entries, #{broken.size} broken", alert: broken.any?)
    flash[broken.empty? ? :notice : :error] =
      broken.empty? ? l(:audit_log_chain_ok, count: count) : l(:audit_log_chain_broken, count: broken.size, ids: broken.first(20).join(', '))
    redirect_to audit_log_path
  end

  # POST
  def lock
    access_log('lock', nil)
    session.delete(SESSION_KEY)
    redirect_to home_path
  end

  private

  # Not an auditor (or no config) -> the page does not exist
  def require_auditor
    return true if User.current.logged? && RedmineAuditLog::Config.auditor?(User.current)

    access_log('denied', 'not an auditor', alert: true) if User.current.logged?
    render_404
    false
  end

  def require_unlocked
    data = session[SESSION_KEY]
    valid = data.is_a?(Hash) && data['user_id'] == User.current.id && data['until'].to_i > Time.now.to_i
    return true if valid

    session.delete(SESSION_KEY)
    redirect_to audit_log_unlock_path
    false
  end

  def locked_out?
    AuditLogEntry.where(category: 'access', event: 'unlock_failed', user_id: User.current.id)
                 .where(AuditLogEntry.arel_table[:created_at].gt(FAILURE_WINDOW.ago)).count >= MAX_FAILURES
  end

  def access_log(event, message, alert: false)
    RedmineAuditLog::Recorder.write(
      RedmineAuditLog::Recorder.request_attributes(request).merge(
        'category' => 'access', 'event' => event, 'alert' => alert,
        'controller_action' => "audit_log##{action_name}", 'message' => message
      )
    )
  end

  def filtered_scope
    scope = AuditLogEntry.all
    table = AuditLogEntry.arel_table
    if (from = parse_date(params[:from]))
      scope = scope.where(table[:created_at].gteq(from.beginning_of_day))
    end
    if (to = parse_date(params[:to]))
      scope = scope.where(table[:created_at].lteq(to.end_of_day))
    end
    scope = scope.where(category: params[:category]) if AuditLogEntry::CATEGORIES.include?(params[:category])
    scope = scope.where(alert: true) if params[:alerts] == '1'
    if params[:user].present?
      scope = scope.where(table[:user_login].matches("%#{AuditLogEntry.sanitize_sql_like(params[:user].strip)}%"))
    end
    scope = scope.where(ip: params[:ip].strip) if params[:ip].present?
    if params[:q].present?
      pattern = "%#{AuditLogEntry.sanitize_sql_like(params[:q].strip)}%"
      scope = scope.where(table[:controller_action].matches(pattern)
                            .or(table[:path].matches(pattern))
                            .or(table[:message].matches(pattern))
                            .or(table[:changes_json].matches(pattern))
                            .or(table[:params].matches(pattern)))
    end
    scope
  end

  def parse_date(value)
    Date.parse(value.to_s) if value.present?
  rescue ArgumentError
    nil
  end

  def filters_summary
    params.to_unsafe_h.slice('from', 'to', 'category', 'alerts', 'user', 'ip', 'q').compact_blank
          .map { |k, v| "#{k}=#{v}" }.join(' ').presence
  end

  def csv(scope)
    Redmine::Export::CSV.generate(encoding: params[:encoding]) do |out|
      out << %w[id time category event alert user auth_method ip user_agent method action path status message
                changes params prev_hash entry_hash]
      scope.each do |e|
        out << [e.id, e.created_at&.localtime&.strftime('%Y-%m-%d %H:%M:%S'), e.category, e.event, e.alert, e.user_login,
                e.auth_method, e.ip, e.user_agent, e.http_method, e.controller_action, e.path, e.status, e.message,
                e.changes_json, e.params, e.prev_hash, e.entry_hash]
      end
    end
  end
end
