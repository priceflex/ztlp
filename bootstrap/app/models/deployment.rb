class Deployment < ApplicationRecord
  belongs_to :machine

  # Phase C — added "skipped" as a valid terminal state. Used by
  # `DeployComponentJob` when the target machine is `Machine#shared?`
  # (auto-seeded shared production NS/Relay rows): we don't SSH into
  # them, but we still want a row in the deployments table so the
  # dashboard timeline shows "skipped — shared infrastructure" instead
  # of a misleading "pending forever" row.
  VALID_STATUSES = %w[pending running success failed skipped].freeze
  validates :status, inclusion: { in: VALID_STATUSES }
  validates :component, presence: true, inclusion: { in: %w[ns relay gateway] }

  scope :recent, -> { order(created_at: :desc) }
  scope :successful, -> { where(status: "success") }
  scope :failed, -> { where(status: "failed") }
  scope :skipped, -> { where(status: "skipped") }

  def duration
    return nil unless started_at
    (finished_at || Time.current) - started_at
  end

  def running?
    status == "running"
  end

  def success?
    status == "success"
  end

  def failed?
    status == "failed"
  end

  def skipped?
    status == "skipped"
  end

  def append_log(line)
    safe_line = line.to_s.encode("UTF-8", invalid: :replace, undef: :replace, replace: "?")
    self.log = ((log || "") + safe_line + "\n").encode("UTF-8", invalid: :replace, undef: :replace, replace: "?")
  end

  def finish!(new_status)
    update!(status: new_status, finished_at: Time.current)
  end
end
