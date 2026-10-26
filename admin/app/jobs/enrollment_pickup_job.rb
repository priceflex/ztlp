# frozen_string_literal: true

# Every 5 minutes: for each pending, unexpired token that names a device, look for the device's KEY
# record on the name server and list the device once it exists (Ztlp::DevicePickup.check). An NS
# error on one token is reported in the result and does not stop the others.
class EnrollmentPickupJob < ApplicationJob
  queue_as :default

  def perform(ns_client: Ztlp::NsClient)
    Enrollment.includes(:zone, :user)
              .where(status: "pending").where.not(device_name: [ nil, "" ])
              .where("expires_at > ?", Time.current)
              .find_each.to_h { |e| [ e.code, Ztlp::DevicePickup.check(e, ns_client: ns_client) ] }
  end
end
