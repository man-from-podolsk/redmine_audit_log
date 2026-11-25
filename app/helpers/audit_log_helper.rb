# frozen_string_literal: true

# Turns journal entries into short Russian/English sentences: "admin changed user ivanov",
# attribute names from Redmine's own translations, browser instead of the full User-Agent.
module AuditLogHelper
  FILTERED = RedmineAuditLog::Sanitizer::FILTERED
  # Shown elsewhere or meaningless to a reader
  HIDDEN_ATTRIBUTES = %w[salt passwd_changed_on twofa_totp_last_used_at].freeze
  ATTRIBUTE_LABELS = { 'hashed_password' => :field_password, 'twofa_totp_key' => :audit_log_attr_twofa,
                       'twofa_scheme' => :audit_log_attr_twofa, 'auth_source_id' => :field_auth_source }.freeze

  # controller#action -> locale key of the phrase (audit_log_do_*)
  PHRASES = {
    'settings#edit' => 'settings', 'settings#plugin' => 'plugin_settings',
    'users#create' => 'user_create', 'users#update' => 'user_update', 'users#destroy' => 'user_destroy',
    'users#bulk_destroy' => 'users_destroy', 'users#bulk_lock' => 'users_lock', 'users#bulk_unlock' => 'users_unlock',
    'groups#create' => 'group_create', 'groups#update' => 'group_update', 'groups#destroy' => 'group_destroy',
    'groups#add_users' => 'group_add_users', 'groups#remove_user' => 'group_remove_user',
    'roles#create' => 'role_create', 'roles#update' => 'role_update', 'roles#destroy' => 'role_destroy',
    'roles#permissions' => 'role_permissions', 'roles#update_permissions' => 'role_permissions',
    'trackers#create' => 'tracker_create', 'trackers#update' => 'tracker_update', 'trackers#destroy' => 'tracker_destroy',
    'issue_statuses#create' => 'status_create', 'issue_statuses#update' => 'status_update', 'issue_statuses#destroy' => 'status_destroy',
    'workflows#edit' => 'workflow', 'workflows#update' => 'workflow', 'workflows#permissions' => 'workflow_fields',
    'workflows#update_permissions' => 'workflow_fields', 'workflows#copy' => 'workflow_copy', 'workflows#duplicate' => 'workflow_copy',
    'custom_fields#create' => 'field_create', 'custom_fields#update' => 'field_update', 'custom_fields#destroy' => 'field_destroy',
    'auth_sources#create' => 'ldap_create', 'auth_sources#update' => 'ldap_update', 'auth_sources#destroy' => 'ldap_destroy',
    'projects#create' => 'project_create', 'projects#update' => 'project_update', 'projects#destroy' => 'project_destroy',
    'projects#archive' => 'project_archive', 'projects#unarchive' => 'project_unarchive',
    'projects#close' => 'project_close', 'projects#reopen' => 'project_reopen',
    'members#create' => 'member_create', 'members#update' => 'member_update', 'members#destroy' => 'member_destroy',
    'principal_memberships#create' => 'member_create', 'principal_memberships#update' => 'member_update',
    'principal_memberships#destroy' => 'member_destroy',
    'versions#create' => 'version_create', 'versions#update' => 'version_update', 'versions#destroy' => 'version_destroy',
    'issue_categories#create' => 'category_create', 'issue_categories#update' => 'category_update',
    'issue_categories#destroy' => 'category_destroy',
    'enumerations#create' => 'enum_create', 'enumerations#update' => 'enum_update', 'enumerations#destroy' => 'enum_destroy',
    'repositories#create' => 'repo_create', 'repositories#update' => 'repo_update', 'repositories#destroy' => 'repo_destroy',
    'queries#create' => 'query_create', 'queries#update' => 'query_update', 'queries#destroy' => 'query_destroy',
    'issues#destroy' => 'issue_destroy', 'attachments#destroy' => 'file_destroy', 'wiki#destroy' => 'wiki_destroy',
    'timelog#destroy' => 'time_destroy', 'news#destroy' => 'news_destroy', 'messages#destroy' => 'message_destroy',
    'documents#destroy' => 'document_destroy', 'journals#update' => 'journal_update',
    'account#lost_password' => 'lost_password', 'account#register' => 'register', 'account#activate' => 'activate',
    'my#account' => 'my_account', 'my#password' => 'my_password', 'my#reset_api_key' => 'my_api_key',
    'my#reset_atom_key' => 'my_atom_key', 'twofa#activate' => 'twofa_on', 'twofa#deactivate' => 'twofa_off',
    'email_addresses#create' => 'email_create', 'email_addresses#destroy' => 'email_destroy',
    'email_addresses#update' => 'email_update'
  }.freeze

  AUTH_REASONS = {
    'invalid login or password' => 'audit_log_reason_invalid',
    'account locked' => 'audit_log_reason_locked',
    'account not activated' => 'audit_log_reason_pending',
    'LDAP account needs registration (missing attributes)' => 'audit_log_reason_ldap_registration'
  }.freeze

  # Count with the right word form. Redmine has no Russian plural rules (it would say "5 события"),
  # so the form is chosen here: one / few / many / other (+ zero), English falls back to one / other.
  def al_count(key, count, **vars)
    forms = ::I18n.t(key)
    return l(key, count: count, **vars) unless forms.is_a?(Hash)

    form = al_plural_form(count, forms)
    (forms[form] || forms[:other]).to_s.gsub('%{count}', count.to_s).then do |text|
      vars.reduce(text) { |out, (k, v)| out.gsub("%{#{k}}", v.to_s) }
    end
  end

  def al_plural_form(count, forms)
    return :zero if count.zero? && forms.key?(:zero)
    return (count == 1 ? :one : :other) unless current_language.to_s.start_with?('ru')

    mod10 = count % 10
    mod100 = count % 100
    if mod10 == 1 && mod100 != 11 then :one
    elsif (2..4).cover?(mod10) && !(12..14).cover?(mod100) then :few
    else :many
    end
  end

  def al_row_class(entry)
    return 'is-alert' if entry.alert

    case entry.category
    when 'auth'
      case entry.event
      when 'login_success' then 'is-ok'
      when 'login_failure', 'login_twofa_failure' then 'is-fail'
      when 'request' then 'is-change'
      else 'is-quiet'
      end
    when 'access' then 'is-access'
    else 'is-change'
    end
  end

  def al_who(entry)
    content_tag(:span, entry.user_login.presence || l(:audit_log_anonymous), class: 'al-who')
  end

  # The sentence after the user's name
  def al_sentence(entry)
    case entry.category
    when 'auth'
      entry.event == 'request' ? al_change_sentence(entry) : al_auth_sentence(entry)
    when 'access' then al_access_sentence(entry)
    else al_change_sentence(entry)
    end
  end

  def al_auth_sentence(entry)
    case entry.event
    when 'login_success'
      note = entry.message == 'with 2FA' ? al_note(l(:audit_log_with_2fa)) : ''.html_safe
      safe_join([l(:audit_log_did_login), note], ' ')
    when 'login_failure'
      reason = AUTH_REASONS[entry.message] ? l(AUTH_REASONS[entry.message]) : entry.message.to_s
      unknown = entry.user_id.nil? && entry.user_login.present? ? al_note(l(:audit_log_unknown_login)) : ''.html_safe
      safe_join([l(:audit_log_did_login_failure, reason: reason), unknown], ' ')
    when 'login_twofa_pending' then l(:audit_log_did_twofa_pending)
    when 'login_twofa_failure' then l(:audit_log_did_twofa_failure)
    when 'logout' then l(:audit_log_did_logout)
    when 'session_end' then l(:audit_log_did_session_end)
    else entry.event
    end
  end

  def al_access_sentence(entry)
    case entry.event
    when 'unlock_failed'
      reason =
        case entry.message.to_s
        when 'wrong journal password' then l(:audit_log_reason_journal_password)
        when 'wrong own password' then l(:audit_log_reason_own_password)
        when /\Awrong own password, journal password\z/ then l(:audit_log_reason_both_passwords)
        else entry.message.to_s
        end
      l(:audit_log_did_unlock_failed, reason: reason)
    when 'verify'
      broken = entry.message.to_s[/(\d+) broken/, 1].to_i
      checked = entry.message.to_s[/(\d+) entries/, 1].to_i
      broken.zero? ? l(:audit_log_did_verify_ok, count: checked) : l(:audit_log_did_verify_broken, count: broken)
    when 'view', 'export'
      note = entry.message.present? ? al_note(l(:audit_log_filter_note, filter: al_filter_text(entry.message))) : ''.html_safe
      safe_join([l("audit_log_did_#{entry.event}"), note], ' ')
    else
      l("audit_log_did_#{entry.event}", default: entry.event)
    end
  end

  # "type=alerts q=petrov" -> "Тревоги, «petrov»"
  def al_filter_text(summary)
    tabs = { 'auth' => :audit_log_tab_auth, 'failed' => :audit_log_tab_failed, 'change' => :audit_log_tab_change,
             'access' => :audit_log_tab_access, 'alerts' => :audit_log_tab_alerts }
    summary.to_s.split(' ').map do |pair|
      key, value = pair.split('=', 2)
      case key
      when 'type' then tabs[value] ? l(tabs[value]) : value
      when 'from' then "#{l(:audit_log_from)} #{value}"
      when 'to' then "#{l(:audit_log_to)} #{value}"
      else "«#{value}»"
      end
    end.join(', ')
  end

  def al_change_sentence(entry)
    key = PHRASES[entry.controller_action]
    phrase =
      if key
        l("audit_log_do_#{key}")
      else
        verb = case entry.controller_action.to_s.split('#').last
               when 'create', 'new', 'add' then l(:audit_log_do_generic_create)
               when 'destroy', 'delete', 'bulk_destroy' then l(:audit_log_do_generic_destroy)
               else l(:audit_log_do_generic_update)
               end
        "#{verb} (#{entry.controller_action})"
      end
    object = al_main_object(entry)
    parts = [phrase]
    parts << content_tag(:b, object) if object
    parts << al_note(l(:audit_log_via_api)) if entry.auth_method == 'API'
    if entry.status.to_i >= 400
      parts << al_note(l(:audit_log_failed_status, status: entry.status))
    end
    safe_join(parts, ' ')
  end

  # Name of the record the request was about, when there is exactly one
  def al_main_object(entry)
    changes = al_changes(entry)
    records = changes.map { |c| [c['model'], c['id']] }.uniq
    return nil unless records.size == 1

    change = changes.first
    label = change['label'].presence
    return nil unless label
    return nil if change['model'] == 'Setting'

    change['model'] == 'Issue' ? "##{change['id']} #{label}" : label
  end

  def al_changes(entry)
    data = entry.changes_data
    data.is_a?(Array) ? data : []
  end

  # "before -> after" list under the sentence
  def al_diff(entry)
    changes = al_changes(entry)
    return ''.html_safe if changes.empty?

    several = changes.map { |c| [c['model'], c['id']] }.uniq.size > 1
    items = []
    changes.each do |change|
      attrs = change['changes'].is_a?(Hash) ? change['changes'] : {}
      attrs = attrs.reject { |attribute, _| HIDDEN_ATTRIBUTES.include?(attribute.to_s) }
      if several
        head = [l("audit_log_change_#{change['event']}", default: change['event'].to_s),
                al_model_name(change['model']), content_tag(:span, change['label'], class: 'al-obj')]
        items << content_tag(:li, safe_join(head, ' '))
      end
      attrs.each do |attribute, (before, after)|
        # On creation, a line that only repeats the record's name adds nothing
        next if change['event'] == 'create' && al_value(attribute, after).to_s == change['label'].to_s

        items << al_diff_line(change, attribute, before, after)
      end
    end
    return ''.html_safe if items.empty?

    content_tag(:ul, safe_join(items), class: 'al-diff')
  end

  def al_diff_line(change, attribute, before, after)
    name = change['model'] == 'Setting' && attribute == 'value' ? l("setting_#{change['label']}", default: change['label'].to_s) : al_attribute_name(attribute)
    label = content_tag(:span, name, class: 'al-attr')
    if before == FILTERED || after == FILTERED
      return content_tag(:li, safe_join([label, al_note(l(:audit_log_value_changed))]))
    end

    before = al_value(attribute, before)
    after = al_value(attribute, after)
    parts = [label]
    if change['event'] == 'create' || before.blank?
      parts << content_tag(:ins, after.presence || l(:audit_log_value_empty))
    else
      parts += [content_tag(:del, before), content_tag(:span, '→', class: 'al-arrow', 'aria-label': l(:audit_log_became)),
                content_tag(:ins, after.presence || l(:audit_log_value_empty))]
    end
    content_tag(:li, safe_join(parts))
  end

  def al_attribute_name(attribute)
    attribute = attribute.to_s
    return l(ATTRIBUTE_LABELS[attribute]) if ATTRIBUTE_LABELS.key?(attribute)
    key = attribute.end_with?('_id') ? attribute.delete_suffix('_id') : attribute
    l("field_#{key}", default: l("field_#{attribute}", default: attribute))
  end

  def al_model_name(model)
    l("audit_log_model_#{model.to_s.underscore}", default: model.to_s)
  end

  # Readable values: yes/no, user status, names instead of ids
  def al_value(attribute, value)
    if attribute.to_s == 'auth_source_id'
      return value.blank? ? l(:audit_log_local_login) : (AuthSource.find_by(id: value)&.name || value.to_s)
    end

    case value
    when true then return l(:general_text_Yes)
    when false then return l(:general_text_No)
    when nil then return ''
    end
    text = value.to_s
    return l(:general_text_Yes) if text == 't'
    return l(:general_text_No) if text == 'f'

    case attribute.to_s
    when 'status'
      { '1' => :status_active, '2' => :status_registered, '3' => :status_locked }[text]&.then { |k| l(k) } || text
    when 'role_id' then Role.find_by(id: text)&.name || text
    when 'tracker_id' then Tracker.find_by(id: text)&.name || text
    when 'status_id', 'old_status_id', 'new_status_id', 'default_status_id' then IssueStatus.find_by(id: text)&.name || text
    when 'project_id', 'parent_id' then Project.find_by(id: text)&.name || text
    when 'user_id', 'author_id', 'assigned_to_id' then Principal.find_by(id: text)&.name || text
    else text.truncate(200)
    end
  rescue StandardError
    value.to_s
  end

  def al_note(text)
    content_tag(:span, text, class: 'al-note')
  end

  # "Firefox, Windows" from the User-Agent
  def al_browser(user_agent)
    ua = user_agent.to_s
    return nil if ua.blank?

    browser = { /YaBrowser/ => 'Яндекс Браузер', /Edg\// => 'Edge', /OPR\/|Opera/ => 'Opera', /Firefox\// => 'Firefox',
                /Chrome\// => 'Chrome', /Safari\// => 'Safari', /curl\// => 'curl' }.find { |re, _| ua.match?(re) }&.last
    os = { /Windows/ => 'Windows', /Android/ => 'Android', /iPhone|iPad/ => 'iOS', /Mac OS X/ => 'macOS',
           /Linux/ => 'Linux' }.find { |re, _| ua.match?(re) }&.last
    [browser, os].compact.join(', ').presence || ua.truncate(40)
  end

  def al_day_title(date)
    today = User.current.today
    prefix =
      if date == today then l(:label_today)
      elsif date == today - 1 then l(:audit_log_yesterday)
      else Array(::I18n.t('date.day_names'))[date.wday]
      end
    "#{prefix.to_s.capitalize}, #{format_date(date)}"
  end

  def al_tab(label, type, count, current)
    query = request.query_parameters.except('page', 'type').merge(type.present? ? { 'type' => type } : {})
    content_tag(:a, safe_join([content_tag(:b, count), label]),
                href: audit_log_path(query), class: ['al-tab', ('al-tab-alert' if type == 'alerts' && count.to_i.positive?)].compact.join(' '),
                'aria-current': (current == type.to_s).to_s)
  end

  def al_filter_link(text, value)
    link_to(text, audit_log_path(request.query_parameters.except('page').merge('q' => value)),
            title: l(:audit_log_filter_by, value: value))
  end
end
