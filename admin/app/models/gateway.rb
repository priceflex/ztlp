# frozen_string_literal: true

# A gateway that fronts zone services and stamps requests with ZTLP
# identity headers (G3). `kind` selects the policy rendering target.
# The settings columns are the `ztlp listen` parameters the Add Service form sets
# (PLAN-services-wizard-and-helpdesk.md slice 4); the install script (slice 5) renders them.
class Gateway < ApplicationRecord
  KINDS = %w[rust_listen elixir].freeze
  STATUSES = %w[planned registered online stale].freeze
  ADDR = /\A[A-Za-z0-9.\-\[\]:]+:\d{1,5}\z/
  IMAGE = %r{\A[A-Za-z0-9][A-Za-z0-9._/:@-]{0,199}\z}
  SUBJECT_MAP_LINE = /\A\h{64}=[a-z0-9@._-]{1,128}\z/

  belongs_to :zone
  has_many :services, dependent: :destroy
  serialize :addresses, coder: JSON
  serialize :subject_map, coder: JSON
  encrypts :header_secret_ct

  before_validation :normalize_name

  def normalize_name
    self.name = name.to_s.strip.downcase
    self.ns_name = "#{name}.#{zone&.name}" if name.present? && zone&.name.present?
  end

  validates :name, presence: true, length: { maximum: 63 },
                   format: { with: Admin::USERNAME, message: "must be a lowercase DNS label" },
                   uniqueness: { scope: :zone_id }
  validates :kind, inclusion: { in: KINDS }
  validates :status, inclusion: { in: STATUSES }
  validates :bind_port, numericality: { only_integer: true, in: 1..65_535, message: "(UDP port) must be 1-65535" }
  validates :max_sessions, numericality: { only_integer: true, in: 1..100_000 }
  validates :ns_server, :relay_addr, format: { with: ADDR, message: "must be host:port" }, allow_blank: true
  validates :image_tag, format: { with: IMAGE, message: "is not a docker image reference" }, allow_blank: true
  validates :host_note, length: { maximum: 200 }
  validate :subject_map_lines

  # The gateway image new installs use unless the form overrides it.
  def self.default_image = ENV.fetch("ZTLP_GATEWAY_IMAGE", "ztlp-gateway-rust:v0.36.0")

  # 32 random bytes as hex: the HMAC key the gateway signs X-ZTLP-* headers with and the app verifies.
  def self.new_header_secret = SecureRandom.hex(32)

  def effective_ns_server = ns_server.presence || zone.ns_addr
  def effective_relay = relay_addr.presence || Array(zone.relay_addrs).first
  def effective_image = image_tag.presence || self.class.default_image

  def rotate_header_secret! = update!(header_secret_ct: self.class.new_header_secret)

  def subject_map_text = Array(subject_map).join("\n")

  def subject_map_text=(text)
    self.subject_map = text.to_s.split(/\r?\n/).map(&:strip).reject(&:empty?).presence
  end

  private

  def subject_map_lines
    bad = Array(subject_map).reject { |l| l.to_s.match?(SUBJECT_MAP_LINE) }
    return if bad.empty?

    errors.add(:subject_map, "lines must look like <64 hex noise key>=<subject> (bad: #{bad.first.to_s.truncate(40)})")
  end
end
