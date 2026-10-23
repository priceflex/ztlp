# frozen_string_literal: true

# One allow-list entry on an application (decision 7). `render` maps the
# subject to the gateway's literal: group:<ns> | role:<v> | <ns> | *.
# NOTE: `subject_type` is deliberately NOT wired as a Rails polymorphic
# association — values like "group"/"role" would be constantized as STI
# class names (NameError). The subject is resolved manually per type.
class PolicyRule < ApplicationRecord
  SUBJECT_TYPES = %w[group role user device any].freeze
  SUBJECT_CLASS = { "group" => "Group", "user" => "User", "device" => "Device" }.freeze

  belongs_to :application

  validates :subject_type, inclusion: { in: SUBJECT_TYPES, message: "is unknown" }
  validate :subject_required_for_typed_rule
  validates :subject_value, inclusion: { in: User::ROLES, message: "must be one of #{User::ROLES.join(", ")}" },
                            if: -> { subject_type == "role" }

  before_validation :pin_subject_value

  def subject_entity
    klass = SUBJECT_CLASS[subject_type]
    return nil unless klass && subject_id
    Object.const_get(klass).find_by(id: subject_id)
  end

  def render
    case subject_type
    when "group"
      # subject_entity is nil when the group row was deleted; the ns_name
      # pinned in subject_value at rule-create time is the literal the
      # gateway will match (stale but honest).
      "group:#{subject_entity&.ns_name || subject_value.presence || "?"}"
    when "role"
      "role:#{subject_value}"
    when "user", "device"
      subject_entity&.ns_name || subject_value
    when "any"
      "*"
    end
  end

  private

  # Pin the subject's ns_name into subject_value at create time so the rule
  # keeps rendering a literal after the entity row is deleted (the gateway
  # matches on the ns_name string, not the DB id).
  def pin_subject_value
    entity = subject_entity
    self.subject_value = entity.ns_name if entity && entity.respond_to?(:ns_name)
    # A cross-zone/missing subject row arrives as subject_id: nil +
    # subject_value: "not_found" (the controller's seam); pin that sentinel so
    # the validation can distinguish "not found in this zone" from "no subject".
    self.subject_value = "not_found" if subject_id.blank? && subject_value == "not_found"
  end

  def subject_required_for_typed_rule
    return if subject_type == "any"
    return if subject_value.present? && subject_value != "not_found"

    if subject_type == "role"
      errors.add(:subject_value, "pick a subject")
    elsif subject_value == "not_found"
      errors.add(:subject_value, "not found in this zone")
    else
      errors.add(:subject_value, "pick a subject")
    end
  end
end
