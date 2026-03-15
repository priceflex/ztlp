# frozen_string_literal: true

# Mirrors a ZTLP NS GROUP record.
class ZtlpGroup < ApplicationRecord
  belongs_to :network
  has_many :group_memberships, dependent: :destroy
  has_many :ztlp_users, through: :group_memberships

  validates :name, presence: true, uniqueness: { scope: :network_id }

  def member_count
    group_memberships.count
  end

  def has_member?(user)
    group_memberships.exists?(ztlp_user: user)
  end
end
