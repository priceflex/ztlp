# frozen_string_literal: true

class PolicyTemplate < ApplicationRecord
  CATEGORIES = %w[employee contractor guest security].freeze

  validates :name, presence: true
  validates :category, presence: true, inclusion: { in: CATEGORIES }
  validates :rules_json, presence: true
  validate :validate_rules_json_format

  scope :built_in, -> { where(built_in: true) }
  scope :by_category, ->(cat) { where(category: cat) }

  def rules
    JSON.parse(rules_json)
  rescue JSON::ParserError
    []
  end

  def rules=(array)
    self.rules_json = array.to_json
  end

  def category_emoji
    case category
    when "employee" then "👤"
    when "contractor" then "🔧"
    when "guest" then "👥"
    when "security" then "🛡️"
    end
  end

  def category_color
    case category
    when "employee" then "blue"
    when "contractor" then "amber"
    when "guest" then "green"
    when "security" then "red"
    end
  end

  # Apply this template to a network, creating policies from its rules
  def apply_to_network!(network)
    created_policies = []
    rules.each do |rule|
      policy = network.policies.create!(
        name: rule["name"] || "#{name} rule",
        description: rule["description"],
        policy_type: rule["policy_type"] || "access",
        priority: rule["priority"] || "normal",
        subject_type: rule["subject_type"] || "everyone",
        subject_value: rule["subject_value"],
        resource_type: rule["resource_type"] || "service",
        resource_value: rule["resource_value"] || "*",
        action: rule["action"] || "allow",
        time_schedule: rule["time_schedule"],
        timezone: rule["timezone"] || "UTC"
      )
      created_policies << policy
    end
    created_policies
  end

  # Seed built-in templates
  def self.seed_built_in!
    templates = [
      {
        name: "Standard Employee",
        description: "Access all internal services during business hours. Suitable for regular employees who need standard access to company resources.",
        category: "employee",
        built_in: true,
        rules_json: [
          {
            name: "Employee — Internal Services",
            description: "Allow access to all internal services",
            policy_type: "access",
            priority: "normal",
            subject_type: "role",
            subject_value: "user",
            resource_type: "service",
            resource_value: "*.internal",
            action: "allow"
          },
          {
            name: "Employee — Business Hours Preferred",
            description: "Access during standard business hours",
            policy_type: "time_based",
            priority: "low",
            subject_type: "role",
            subject_value: "user",
            resource_type: "service",
            resource_value: "*.internal",
            action: "allow",
            time_schedule: "MON-FRI 09:00-17:00"
          }
        ].to_json
      },
      {
        name: "Contractor — Limited",
        description: "Specific services only with time limits. No admin access to any resources. Suitable for external contractors.",
        category: "contractor",
        built_in: true,
        rules_json: [
          {
            name: "Contractor — Specific Services",
            description: "Allow access to contractor-designated services only",
            policy_type: "access",
            priority: "normal",
            subject_type: "group",
            subject_value: "contractors",
            resource_type: "service",
            resource_value: "contractor.internal",
            action: "allow"
          },
          {
            name: "Contractor — Deny Admin",
            description: "Deny access to admin services",
            policy_type: "access",
            priority: "high",
            subject_type: "group",
            subject_value: "contractors",
            resource_type: "service",
            resource_value: "admin.*",
            action: "deny"
          },
          {
            name: "Contractor — Business Hours Only",
            description: "Restrict to business hours",
            policy_type: "time_based",
            priority: "normal",
            subject_type: "group",
            subject_value: "contractors",
            resource_type: "service",
            resource_value: "contractor.internal",
            action: "allow",
            time_schedule: "MON-FRI 08:00-18:00"
          }
        ].to_json
      },
      {
        name: "Guest — Minimal",
        description: "Internet-only access through ZTLP. No access to any internal services. Suitable for visitors and guest accounts.",
        category: "guest",
        built_in: true,
        rules_json: [
          {
            name: "Guest — Internet Only",
            description: "Allow internet access through ZTLP gateway",
            policy_type: "access",
            priority: "normal",
            subject_type: "group",
            subject_value: "guests",
            resource_type: "zone",
            resource_value: "internet",
            action: "allow"
          },
          {
            name: "Guest — Deny Internal",
            description: "Deny access to all internal services",
            policy_type: "access",
            priority: "high",
            subject_type: "group",
            subject_value: "guests",
            resource_type: "service",
            resource_value: "*.internal",
            action: "deny"
          }
        ].to_json
      },
      {
        name: "IT Admin — Full Access",
        description: "Full unrestricted access to all services, zones, and resources at all times. For trusted IT administrators.",
        category: "security",
        built_in: true,
        rules_json: [
          {
            name: "IT Admin — All Services",
            description: "Full access to all services",
            policy_type: "access",
            priority: "high",
            subject_type: "role",
            subject_value: "admin",
            resource_type: "service",
            resource_value: "*",
            action: "allow"
          },
          {
            name: "IT Admin — All Zones",
            description: "Full access to all zones",
            policy_type: "access",
            priority: "high",
            subject_type: "role",
            subject_value: "admin",
            resource_type: "zone",
            resource_value: "*",
            action: "allow"
          }
        ].to_json
      },
      {
        name: "Restricted — Quarantine",
        description: "Deny all access except the remediation portal. Use for compromised accounts or devices pending investigation.",
        category: "security",
        built_in: true,
        rules_json: [
          {
            name: "Quarantine — Deny All",
            description: "Deny access to all services",
            policy_type: "access",
            priority: "high",
            subject_type: "group",
            subject_value: "quarantine",
            resource_type: "service",
            resource_value: "*",
            action: "deny"
          },
          {
            name: "Quarantine — Allow Remediation",
            description: "Allow access to remediation portal only",
            policy_type: "access",
            priority: "high",
            subject_type: "group",
            subject_value: "quarantine",
            resource_type: "service",
            resource_value: "remediation.internal",
            action: "allow"
          }
        ].to_json
      }
    ]

    templates.each do |attrs|
      PolicyTemplate.find_or_create_by!(name: attrs[:name]) do |t|
        t.description = attrs[:description]
        t.category = attrs[:category]
        t.built_in = attrs[:built_in]
        t.rules_json = attrs[:rules_json]
      end
    end
  end

  private

  def validate_rules_json_format
    return if rules_json.blank?
    parsed = JSON.parse(rules_json)
    unless parsed.is_a?(Array)
      errors.add(:rules_json, "must be a JSON array")
      return
    end
    parsed.each_with_index do |rule, i|
      unless rule.is_a?(Hash)
        errors.add(:rules_json, "rule #{i + 1} must be a JSON object")
      end
    end
  rescue JSON::ParserError
    errors.add(:rules_json, "must be valid JSON")
  end
end
