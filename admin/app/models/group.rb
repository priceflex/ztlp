# frozen_string_literal: true

class Group < ApplicationRecord
  belongs_to :zone
  has_many :group_memberships, dependent: :destroy
  has_many :users, through: :group_memberships

  NS_NAME_MAX = 255

  before_validation :normalize_name

  def normalize_name
    self.name = name.to_s.strip.downcase
    self.ns_name = "#{name}.groups.#{zone&.name}" if name.present? && zone&.name.present?
  end

  validates :name, presence: true, length: { maximum: 63 },
                   format: { with: Admin::USERNAME, message: "must be a lowercase DNS label" },
                   uniqueness: { scope: :zone_id }
  validates :ns_name, presence: true, length: { maximum: NS_NAME_MAX }, allow_nil: true

  def member?(user) = group_memberships.exists?(user_id: user.id)
end
