# frozen_string_literal: true

# The Add Service form (PLAN-services-wizard-and-helpdesk.md slice 4): one page that creates a
# planned gateway, its service and a starting access rule in one transaction. Nothing is published
# and nothing runs anywhere; the service page then shows the gateway install script (slice 5).
class ServiceSetup
  include ActiveModel::Model
  include ActiveModel::Attributes

  PROTOCOLS = %w[http tcp].freeze
  # No "user" choice: Rust gateways check the DEVICE, so a user rule never matches (use a group).
  ACCESS = %w[none any group device role].freeze

  attribute :fqdn, :string
  attribute :host_note, :string
  attribute :backend, :string
  attribute :protocol, :string, default: "http"
  attribute :inject_headers, :boolean, default: true
  attribute :access, :string, default: "none"
  attribute :access_group_id, :integer
  attribute :access_device_id, :integer
  attribute :access_role, :string
  attribute :description, :string
  attribute :min_assurance, :integer, default: 1
  # Advanced
  attribute :bind_port, :integer, default: 23_097
  attribute :ns_server, :string
  attribute :relay_addr, :string
  attribute :max_sessions, :integer, default: 100
  attribute :punch, :boolean, default: true
  attribute :image_tag, :string
  attribute :subject_map_text, :string

  attr_reader :service, :gateway, :zone

  validates :fqdn, presence: true
  validates :backend, presence: true
  validates :protocol, inclusion: { in: PROTOCOLS }
  validates :access, inclusion: { in: ACCESS }
  validate :name_in_a_zone
  validate :access_subject_present

  def label = @label

  # Runs every validation (own, gateway, service) so one submit shows every problem.
  def save
    @fqdn_resolved = false
    resolve_name
    build_records
    own_ok = valid?
    gw_ok = @gateway.valid?
    svc_ok = @service.valid?
    copy_errors(@gateway, "Gateway")
    copy_errors(@service, "Service", skip: %i[gateway])
    return false unless own_ok && gw_ok && svc_ok && errors.empty?

    Gateway.transaction do
      @gateway.save!
      @service.gateway = @gateway
      @service.save!
      rule = starting_rule
      rule&.save!
    end
    true
  rescue ActiveRecord::RecordInvalid => e
    errors.add(:base, e.record.errors.full_messages.to_sentence)
    false
  end

  private

  def resolve_name
    self.fqdn = fqdn.to_s.strip.downcase
    @zone = Ztlp::ServiceRegistrar.zone_for(fqdn)
    @label = @zone && Ztlp::ServiceRegistrar.label_for(fqdn, @zone)
  end

  def build_records
    headers = protocol == "http" && inject_headers
    zone = @zone || Zone.default
    @gateway = Gateway.new(
      zone: zone, name: @label || "invalid", kind: "rust_listen", status: "planned",
      host_note: host_note.to_s.strip.presence, bind_port: bind_port, max_sessions: max_sessions,
      punch: punch, inject_headers: headers, policy_file: true,
      header_secret_ct: (Gateway.new_header_secret if headers),
      ns_server: ns_server.to_s.strip.presence, relay_addr: relay_addr.to_s.strip.presence,
      image_tag: image_tag.to_s.strip.presence, subject_map_text: subject_map_text
    )
    @service = Service.new(gateway: @gateway, name: @label || "invalid", backend: backend.to_s.strip,
                           protocol: protocol, min_assurance: min_assurance, description: description.to_s.strip.presence)
  end

  def starting_rule
    attrs = case access
    when "any" then { subject_type: "any" }
    when "group" then { subject_type: "group", subject_id: access_group_id }
    when "device" then { subject_type: "device", subject_id: access_device_id }
    when "role" then { subject_type: "role", subject_value: access_role }
    end
    attrs && @service.policy_rules.build(attrs.merge(position: 0))
  end

  def name_in_a_zone
    return if fqdn.blank?

    if @zone.nil?
      errors.add(:fqdn, "#{fqdn} is in no zone this panel knows (add the zone first)")
    elsif @label.nil?
      errors.add(:fqdn, "must be one label inside #{@zone.name} (e.g. www.#{@zone.name})")
    elsif @zone.gateways.exists?(name: @label)
      errors.add(:fqdn, "#{fqdn} already exists: open it from the Services list")
    end
  end

  def access_subject_present
    return unless @zone

    ok = case access
    when "group" then @zone.groups.exists?(id: access_group_id)
    when "device" then @zone.devices.where.not(status: "revoked").exists?(id: access_device_id)
    when "role" then User::ROLES.include?(access_role)
    else true
    end
    errors.add(:access, "pick the #{access} that may reach this service") unless ok
  end

  def copy_errors(record, prefix, skip: [])
    record.errors.each do |err|
      next if skip.include?(err.attribute)
      next if err.attribute == :name && !errors[:fqdn].empty? # already explained on the full name

      errors.add(:base, "#{prefix} #{err.attribute.to_s.humanize(capitalize: false)} #{err.message}")
    end
  end
end
