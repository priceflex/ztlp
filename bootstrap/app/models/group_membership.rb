# frozen_string_literal: true

# Join table between ZtlpGroup and ZtlpUser.
class GroupMembership < ApplicationRecord
  belongs_to :ztlp_group
  belongs_to :ztlp_user

  validates :ztlp_user_id, uniqueness: { scope: :ztlp_group_id, message: "is already a member of this group" }
end
