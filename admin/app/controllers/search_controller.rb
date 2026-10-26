# frozen_string_literal: true

# Slice 11b: global search (spec Slice 11, §2.1).
#
# GET /search.json?q= — ILIKE over users (username / display_name / email via
# deterministic exact), devices (name / node_id), groups (name / description),
# services (name); max 20; JSON {type,id,name,sub,url} only — never HTML.
# No audit row (a search is not a mutation, and the query string must not
# reach the audit log).
class SearchController < ApplicationController
  PER_PAGE = 20

  def index
    q = params[:q].to_s.strip
    render json: [], status: :ok, layout: false and return if q.empty?

    like = "%#{ActiveRecord::Base.sanitize_sql_like(q.downcase)}%"
    rows = user_rows(q, like) + device_rows(like) + group_rows(like) + service_rows(like)
    render json: rows.first(20), status: :ok, layout: false
  end

  private

  def user_rows(q, like)
    scope = @zone.users.where("LOWER(username) LIKE :like OR LOWER(display_name) LIKE :like OR LOWER(ns_name) LIKE :like", like: like)
    # email is `encrypts deterministic: true`, so where(email:) is an exact
    # ciphertext match in SQL (no plaintext, no per-row decrypt) — same trick
    # as the Users index filter; a non-address query simply matches nobody.
    email_ids = @zone.users.where(email: [ q, q.downcase ].uniq).pluck(:id)
    scope = scope.or(@zone.users.where(id: email_ids)) if email_ids.any?

    scope.order(:username).limit(2 * PER_PAGE).map do |u|
      { type: "user", id: u.id, name: u.display_name, sub: u.ns_name, url: "/users/#{u.id}" }
    end
  end

  def device_rows(like)
    @zone.devices
           .where("LOWER(name) LIKE :like OR LOWER(ns_name) LIKE :like OR LOWER(node_id_hex) LIKE :like", like: like)
           .order(:name).limit(2 * PER_PAGE).map do |d|
             { type: "device", id: d.id, name: d.name, sub: d.ns_name, url: "/devices/#{d.id}" }
           end
  end

  def group_rows(like)
    @zone.groups
          .where("LOWER(name) LIKE :like OR LOWER(description) LIKE :like OR LOWER(ns_name) LIKE :like", like: like)
          .order(:name).limit(2 * PER_PAGE).map do |g|
            { type: "group", id: g.id, name: g.name, sub: g.description.presence || g.ns_name,
              url: "/groups/#{g.id}" }
          end
  end

  def service_rows(like)
    Service.where(gateway: @zone.gateways)
               .where("LOWER(name) LIKE :like OR LOWER(backend) LIKE :like", like: like)
               .order(:name).limit(2 * PER_PAGE).map do |a|
                 { type: "service", id: a.id, name: a.name,
                   sub: [ a.protocol, a.backend ].compact_blank.join(" "),
                   url: "/services/#{a.id}" }
               end
  end
end
