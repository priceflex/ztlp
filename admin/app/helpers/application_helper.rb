# frozen_string_literal: true

module ApplicationHelper
  # Directory rail navigation (mock NAV, docs/admin-panel/ui-mock-2026-10-20.html).
  # [section label, [[route, label, icon], ...]]. Slices 6-11 fill the
  # missing pages; until then the route renders what exists.
  NAV = [
    [
      "Directory",
      [ [ "root", "Overview", "grid" ], [ "users", "Users", "user" ],
        [ "devices", "Devices", "laptop" ], [ "groups", "Groups", "layers" ] ]
    ],
    [
      "Access",
      [ [ "services", "Services", "app" ], [ "policies", "Policies", "shield" ],
        [ "enrollments", "Enrollments", "key" ] ]
    ],
    [
      "Operations",
      [ [ "audit_logs", "Audit log", "scroll" ], [ "zone", "Name server", "globe" ],
        [ "admins", "Administrators", "user" ] ]
    ]
  ].freeze

  # Mock icon glyphs (svg inner content) for the rail + topbar.
  NAV_ICONS = {
    "grid" => '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
    "user" => '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-6 8-6s8 2 8 6"/>',
    "laptop" => '<rect x="4" y="5" width="16" height="11" rx="1.5"/><path d="M2 19.5h20"/>',
    "layers" => '<path d="M12 3 2.5 8 12 13l9.5-5L12 3z"/><path d="m2.5 13 9.5 5 9.5-5"/><path d="m2.5 17.5 9.5 4 9.5-4" opacity=".55"/>',
    "app" => '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M7 6.5h.01M10 6.5h.01"/>',
    "shield" => '<path d="M12 3 4.5 6v6c0 4.4 3.2 8 7.5 9 4.3-1 7.5-4.6 7.5-9V6L12 3z"/><path d="m9 12 2.2 2.2L15.5 10"/>',
    "key" => '<circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.8-9.8M17 6l3 3M14.5 8.5l2 2"/>',
    "scroll" => '<path d="M8 3.5h11v14.5a2.5 2.5 0 0 1-2.5 2.5H6"/><path d="M8 3.5a2 2 0 0 0-4 0V7h4"/><path d="M8 3.5V18a2.5 2.5 0 0 1-2.5 2.5"/><path d="M11.5 8.5h4.5M11.5 12.5h4.5"/>',
    "globe" => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.4 2.5 3.7 5.5 3.7 9s-1.3 6.5-3.7 9c-2.4-2.5-3.7-5.5-3.7-9S9.6 5.5 12 3z"/>',
    "search" => '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.6-3.6"/>',
    "moon" => '<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',
    "menu" => '<path d="M4 7h16M4 12h16M4 17h16"/>'
  }.freeze

  def nav_icon(name, size = 18)
    %(<svg class="ic" width="#{size}" height="#{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">#{NAV_ICONS.fetch(name, "")}</svg>).html_safe
  end

  def current_route
    case request.path
    when %r{\A/(?:services|applications|gateways)\b} then "services"
    when %r{\A/(users|devices|groups|policies|enrollments|zone|admins|audit_logs)\b}
      Regexp.last_match(1)
    else
      "root"
    end
  end

  # Rails path for a NAV route token. Pages not built yet (Slices 6-11)
  # resolve to a plain path; Rails 404s honestly until they land.
  def nav_href(route)
    case route
    when "root" then root_path
    when "users" then users_path
    when "devices" then "/devices"
    when "groups" then groups_path
    when "services" then services_path
    when "policies" then "/policies"
    when "enrollments" then enrollments_path
    when "zone" then "/zone"
    when "admins" then admins_path
    when "audit_logs" then audit_logs_path
    else "/#{route}"
    end
  end

  def initials(name)
    name.to_s.split(/\s+/).map { |w| w[0] }.first(2).join.upcase
  end

  # Status badge (mock design: dot + label; ok/warn/bad tone classes).
  STATUS_TONE = {
    "active" => "ok", "enrolled" => "ok", "redeemed" => "ok", "registered" => "ok",
    "invited" => "warn", "pending" => "warn",
    "disabled" => "bad", "revoked" => "bad", "expired" => "bad", "stale" => "bad"
  }.freeze

  def status_badge(status)
    tone = STATUS_TONE.fetch(status.to_s, "")
    tag.span(status, class: [ "badge", tone ].compact_blank.join(" "))
  end
end
