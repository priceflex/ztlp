module ApplicationHelper
  def nav_link_class(path)
    base = "rounded-md px-3 py-2 text-sm font-medium"
    if request.path == path || (path != "/" && request.path.start_with?(path))
      "#{base} bg-ztlp-900 text-white"
    else
      "#{base} text-gray-300 hover:bg-ztlp-700 hover:text-white"
    end
  end

  def status_badge(status)
    colors = {
      "active"       => "bg-green-100 text-green-800",
      "ready"        => "bg-green-100 text-green-800",
      "success"      => "bg-green-100 text-green-800",
      "created"      => "bg-blue-100 text-blue-800",
      "pending"      => "bg-yellow-100 text-yellow-800",
      "suspended"    => "bg-yellow-100 text-yellow-800",
      "deploying"    => "bg-blue-100 text-blue-800",
      "provisioning" => "bg-blue-100 text-blue-800",
      "running"      => "bg-blue-100 text-blue-800",
      "error"        => "bg-red-100 text-red-800",
      "failed"       => "bg-red-100 text-red-800",
      "offline"      => "bg-gray-100 text-gray-800",
      "expired"      => "bg-gray-100 text-gray-800",
      "exhausted"    => "bg-gray-100 text-gray-800",
      "revoked"      => "bg-red-100 text-red-800",
      "enrolled"     => "bg-green-100 text-green-800"
    }
    color = colors[status] || "bg-gray-100 text-gray-800"
    content_tag(:span, status, class: "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium #{color}")
  end

  def role_badges(roles_string)
    roles_string.split(",").map(&:strip).reject(&:empty?).map do |role|
      color = case role
              when "ns" then "bg-purple-100 text-purple-800"
              when "relay" then "bg-indigo-100 text-indigo-800"
              when "gateway" then "bg-cyan-100 text-cyan-800"
              end
      content_tag(:span, role, class: "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium #{color}")
    end.join(" ").html_safe
  end

  def time_ago_short(time)
    return "never" if time.nil?
    if time > Time.current
      "in " + time_ago_in_words(time)
    else
      time_ago_in_words(time) + " ago"
    end
  end

  def health_status_badge(status)
    colors = {
      "healthy"  => "bg-green-100 text-green-800",
      "degraded" => "bg-yellow-100 text-yellow-800",
      "down"     => "bg-red-100 text-red-800",
      "unknown"  => "bg-gray-100 text-gray-800"
    }
    color = colors[status.to_s] || "bg-gray-100 text-gray-800"
    content_tag(:span, status || "unknown",
      class: "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium #{color}")
  end

  def health_status_icon(status)
    case status.to_s
    when "healthy"  then "🟢"
    when "degraded" then "🟡"
    when "down"     then "🔴"
    else "⚪"
    end
  end

  def health_border_color(status)
    case status.to_s
    when "healthy"  then "border-green-500"
    when "degraded" then "border-yellow-500"
    when "down"     then "border-red-500"
    else "border-gray-300"
    end
  end

  def format_uptime(seconds)
    return "N/A" unless seconds
    seconds = seconds.to_i
    if seconds < 60
      "#{seconds}s"
    elsif seconds < 3600
      "#{seconds / 60}m #{seconds % 60}s"
    elsif seconds < 86400
      "#{seconds / 3600}h #{(seconds % 3600) / 60}m"
    else
      "#{seconds / 86400}d #{(seconds % 86400) / 3600}h"
    end
  end

  # ZTLP tunnel connectivity indicator — red/green dot with tooltip
  def ztlp_tunnel_indicator(machine)
    if machine.ztlp_tunnel_reachable?
      latency = machine.ztlp_tunnel_latency_ms
      checked = machine.ztlp_tunnel_checked_at
      title = "ZTLP tunnel: connected"
      title += " (#{latency}ms)" if latency
      title += " — checked #{time_ago_short(checked)}" if checked
      content_tag(:span, class: "inline-flex items-center gap-1", title: title) do
        content_tag(:span, "", class: "inline-block h-2.5 w-2.5 rounded-full bg-green-500 shadow-sm shadow-green-500/50") +
          content_tag(:span, "ZTLP", class: "text-xs font-medium text-green-700")
      end
    elsif machine.ztlp_tunnel_checked_at.present?
      error = machine.ztlp_tunnel_error || "unreachable"
      title = "ZTLP tunnel: #{error}"
      content_tag(:span, class: "inline-flex items-center gap-1", title: title) do
        content_tag(:span, "", class: "inline-block h-2.5 w-2.5 rounded-full bg-red-500 shadow-sm shadow-red-500/50") +
          content_tag(:span, "ZTLP", class: "text-xs font-medium text-red-600")
      end
    else
      content_tag(:span, class: "inline-flex items-center gap-1", title: "ZTLP tunnel: not checked") do
        content_tag(:span, "", class: "inline-block h-2.5 w-2.5 rounded-full bg-gray-300") +
          content_tag(:span, "ZTLP", class: "text-xs font-medium text-gray-400")
      end
    end
  end

  def alert_count_badge
    count = Alert.active_count
    return "" if count == 0
    content_tag(:span, count,
      class: "ml-1 inline-flex items-center justify-center rounded-full bg-red-500 px-1.5 py-0.5 text-xs font-bold text-white")
  end

  # Identity helpers

  def user_role_badge(role)
    color = case role
            when "admin" then "bg-red-100 text-red-800"
            when "tech"  then "bg-amber-100 text-amber-800"
            else "bg-blue-100 text-blue-800"
            end
    content_tag(:span, role, class: "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium #{color}")
  end

  def user_avatar(user, size: "h-8 w-8", text_size: "text-xs")
    bg = case user.role
         when "admin" then "bg-red-500"
         when "tech"  then "bg-amber-500"
         else "bg-blue-500"
         end
    content_tag(:span, user.initials,
      class: "inline-flex items-center justify-center rounded-full #{size} #{bg} #{text_size} font-medium text-white",
      title: "#{user.name} (#{user.role})")
  end

  def identity_tab_class(current_tab, tab_name)
    base = "inline-flex items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium whitespace-nowrap"
    if current_tab == tab_name
      "#{base} border-ztlp-500 text-ztlp-600"
    else
      "#{base} border-transparent text-gray-500 hover:border-gray-300 hover:text-gray-700"
    end
  end
end
