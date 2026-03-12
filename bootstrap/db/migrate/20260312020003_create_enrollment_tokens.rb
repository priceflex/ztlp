class CreateEnrollmentTokens < ActiveRecord::Migration[7.1]
  def change
    create_table :enrollment_tokens do |t|
      t.references :network, null: false, foreign_key: true
      t.string :token_id, null: false           # short unique identifier
      t.string :token_uri                       # ztlp://enroll/... URI
      t.text :qr_svg                            # SVG QR code
      t.integer :max_uses, null: false, default: 1
      t.integer :current_uses, null: false, default: 0
      t.datetime :expires_at, null: false
      t.string :status, null: false, default: "active" # active, exhausted, expired, revoked
      t.string :allowed_roles                   # comma-separated roles this token can enroll
      t.text :notes

      t.timestamps
    end

    add_index :enrollment_tokens, :token_id, unique: true
    add_index :enrollment_tokens, :status
    add_index :enrollment_tokens, [:network_id, :status]
  end
end
