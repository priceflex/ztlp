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
      "deploying"    => "bg-blue-100 text-blue-800",
      "provisioning" => "bg-blue-100 text-blue-800",
      "running"      => "bg-blue-100 text-blue-800",
      "error"        => "bg-red-100 text-red-800",
      "failed"       => "bg-red-100 text-red-800",
      "offline"      => "bg-gray-100 text-gray-800",
      "expired"      => "bg-gray-100 text-gray-800",
      "exhausted"    => "bg-gray-100 text-gray-800",
      "revoked"      => "bg-red-100 text-red-800"
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
    time_ago_in_words(time) + " ago"
  end
end
