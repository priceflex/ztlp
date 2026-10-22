# frozen_string_literal: true

require "test_helper"
require "fugit"

# The schedule must be loaded by solid_queue ITSELF (1.7: <env>: <key>: {class:, schedule:}).
# A file that solid_queue silently ignores means the jobs never run.
class RecurringScheduleTest < ActiveSupport::TestCase
  EXPECTED = {
    "RepublishNsJob" => "every 6 hours",
    "ReconcileNsJob" => "every 30 minutes",
    "ExpireEnrollmentsJob" => "every 5 minutes"
  }.freeze

  def loaded(env)
    SolidQueue::Configuration.new.send(:config_from, Rails.root.join("config/recurring.yml"), env: env)
  end

  test "solid_queue reads the three recurring jobs for production and development" do
    %w[production development].each do |env|
      got = loaded(env).to_h { |_k, v| [ v[:class], v[:schedule] ] }
      assert_equal EXPECTED, got, "recurring.yml as solid_queue reads it for #{env}"
    end
  end

  test "every task's schedule parses (Fugit, as solid_queue does) and its class is a job" do
    tasks = loaded("production")
    assert_equal 3, tasks.size
    tasks.each do |key, opts|
      assert Fugit.parse(opts[:schedule]), "#{key}: schedule #{opts[:schedule].inspect} must parse"
      assert opts[:class].constantize < ApplicationJob, "#{key}: #{opts[:class]} must be a job"
    end
  end
end
