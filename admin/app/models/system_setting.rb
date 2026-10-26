# frozen_string_literal: true

class SystemSetting < ApplicationRecord
  self.primary_key = "key"
  encrypts :value_ct

  def self.[](key) = find_by(key: key)&.value_ct

  def self.[]=(key, value)
    rec = find_or_initialize_by(key: key)
    rec.value_ct = value
    rec.updated_at = Time.current
    rec.save!
  end

  def self.delete_key(key) = where(key: key).delete_all
end
