class AddZtlpUserIdToEnrollmentTokens < ActiveRecord::Migration[7.1]
  def change
    add_reference :enrollment_tokens, :ztlp_user, null: true, foreign_key: true
  end
end
