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

  validates :subject_type, inclusion: { in: SUBJECT_TYPES }
  validate :subject_required_for_typed_rule

  def subject_entity
    klass = SUBJECT_CLASS[subject_type]
    return nil unless klass && subject_id
    Object.const_get(klass).find_by(id: subject_id)
  end

  def render
    case subject_type
    when "group"
      "group:#{subject_entity&.ns_name || subject_value}"
    when "role"
      "role:#{subject_value}"
    when "user", "device"
      subject_entity&.ns_name || subject_value
    when "any"
      "*"
    end
  end

  private

  def subject_required_for_typed_rule
    return if subject_type == "any"
    return if subject_entity&.ns_name.present?
    return if subject_type == "role" && subject_value.present?

    errors.add(:subject_value, "is required for this subject type")
  end
end
