# frozen_string_literal: true

# Refuses requests that the browser marks as coming from another website.
#
# The panel signs an administrator in from the ZTLP tunnel itself, so the sign-in travels with every
# request the browser makes, whichever page asked for it. Without this check a page on any other site
# could make the browser submit a form here as the administrator. Browsers report where a request came
# from in the Sec-Fetch-* headers, which page scripts cannot set or remove.
#
# Served: requests from the panel's own pages (same-origin), addresses typed or bookmarked (none),
# requests without the headers (command-line clients; the anti-forgery token still applies to them),
# and a plain link click from another site (top-level GET navigation), so links in mail keep working.
# Over plain http, where browsers omit Sec-Fetch-*, a changing request whose Origin is another host
# is refused instead.
# Refused: everything else from another origin, including other sites in the same ZTLP zone
# ("same-site"), which a SameSite cookie does not stop.
module CrossSiteGuard
  extend ActiveSupport::Concern

  OWN_ORIGIN = %w[same-origin none].freeze

  included do
    prepend_before_action :refuse_cross_site_request
  end

  private

  def refuse_cross_site_request
    site = request.headers["Sec-Fetch-Site"].to_s.downcase
    if site.empty?
      # Browsers send Sec-Fetch-* only to https pages. Over plain http fall back to Origin, which
      # they attach to every cross-origin request that can change something.
      return unless foreign_origin_on_unsafe_method?

      site = "origin-mismatch"
    else
      return if OWN_ORIGIN.include?(site) || top_level_link_click?
    end

    AuditLog.record!("auth.cross_site_blocked", ip: request.remote_ip, status: "denied",
                     details: { method: request.request_method, path: request.path, site: site,
                                origin: request.headers["Origin"].to_s.first(200) })
    render plain: "Refused: this request was sent by another website.", status: :forbidden
  end

  def foreign_origin_on_unsafe_method?
    return false if request.get? || request.head?

    origin = request.headers["Origin"].to_s
    return false if origin.empty?

    host = begin
      URI.parse(origin).host
    rescue URI::InvalidURIError
      nil
    end
    !host.to_s.casecmp?(request.host)
  end

  def top_level_link_click?
    (request.get? || request.head?) &&
      request.headers["Sec-Fetch-Mode"].to_s.casecmp?("navigate") &&
      request.headers["Sec-Fetch-Dest"].to_s.casecmp?("document")
  end
end
