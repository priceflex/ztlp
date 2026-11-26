# frozen_string_literal: true

# Every minute: for each pending, unexpired token that names a device, look for the device's KEY
# record on the name server and list the device once it exists (Ztlp::DevicePickup.check), which also
# publishes its DEVICE record (owner) so gateways see the person right away. A failure on one token
# (NS error, or a database conflict such as a node id already on another device) is reported in the
# result as :error / :ns_error and does not stop the others. Then retry any owned device whose DEVICE
# record never reached the NS (Ztlp::DevicePickup.publish_pending!).
class EnrollmentPickupJob < ApplicationJob
  queue_as :default

  def perform(ns_client: Ztlp::NsClient)
    Enrollment.includes(:zone, :user)
              .where(status: "pending")
              .where("COALESCE(device_name, '') <> '' OR COALESCE(token_ref, '') <> ''")
              .where("expires_at > ?", Time.current)
              .find_each.to_h do |e|
                result = begin
                  Ztlp::DevicePickup.check(e, ns_client: ns_client)
                rescue ActiveRecord::ActiveRecordError => err
                  Rails.logger.error("enrollment_pickup #{e.code}: #{err.class}: #{err.message}")
                  :error
                end
                [ e.code, result ]
              end
              .tap { Ztlp::DevicePickup.publish_pending!(ns_client: ns_client) }
  end
end
