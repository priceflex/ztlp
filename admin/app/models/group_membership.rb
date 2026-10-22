# frozen_string_literal: true

class GroupMembership < ApplicationRecord
  belongs_to :group
  belongs_to :user
  belongs_to :added_by_admin, class_name: "Admin", optional: true

  validates :user_id, uniqueness: { scope: :group_id }
end
