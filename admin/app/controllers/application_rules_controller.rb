# frozen_string_literal: true

# Slice 9b sub-slice 4: policy-rule add/remove on the application show page.
#
# POST   /apps/:id/rules        add a rule (subject_type + subject_id or
#                                subject_value); position auto = count + 1;
#                                audit rule.add; redirect back with the
#                                deploy hint (rule changes need a gateway
#                                restart — same contract as the other 9b
#                                sub-slices: NOTHING is published to the NS).
# DELETE /apps/:id/rules/:rid   remove one rule (scoped to the application,
#                                which is itself zone-scoped); audit
#                                rule.remove; unknown rule -> 404.
#
# Subjects: group/user/device are picked from rows in THIS zone (a subject id
# from another zone re-renders with an error, nothing persisted); role is free
# text; any needs no subject. The subject's ns_name is pinned into subject_value
# at create time (PolicyRule#pin_subject_value), so the rendered literal
# survives entity deletion.
class ApplicationRulesController < ApplicationController
  before_action :require_write_access, only: %i[create destroy]

  PICKED_TYPES = %w[group user device].freeze

  def create
    @application = zone_application
    @rule = @application.policy_rules.new(rule_attrs)
    if @rule.save
      audit!("rule.add", target: @application, rule: @rule.render)
      redirect_to application_path(@application),
                  notice: "Rule #{@rule.render} added. Deploy the rendered policy and restart the gateway to make it live."
    else
      @rule_errors = @rule.errors.full_messages
      load_show_context
      render "applications/show", status: :unprocessable_content
    end
  end

  def destroy
    @application = zone_application
    rule = @application.policy_rules.find(params[:id]) # unknown -> 404
    literal = rule.render
    destroyed = rule.destroy
    unless destroyed
      audit!("rule.remove", target: @application, status: "failed", rule: literal,
                                      error: "row survived: #{rule.errors.full_messages.to_sentence}")
      return redirect_to application_path(@application),
                         alert: "Could not remove rule #{literal}: #{rule.errors.full_messages.to_sentence}"
    end

    audit!("rule.remove", target: @application, rule: literal)
    redirect_to application_path(@application),
                notice: "Rule #{literal} removed. Deploy the rendered policy and restart the gateway to make it live."
  end

  private

  def zone_application
    @application ||= Application
                      .where(id: params[:application_id])
                      .where(gateway_id: @zone.gateways.select(:id))
                      .includes(gateway: :zone, policy_rules: [])
                      .first
    raise ActiveRecord::RecordNotFound, "application" if @application.nil?

    @application
  end

  def load_show_context
    @zone_users = @zone.users.order(:display_name).limit(500)
    @zone_devices = @zone.devices.order(:name).limit(500)
    @zone_groups = @zone.groups.order(:name).limit(500)
  end

  def rule_attrs
    type = params.fetch(:subject_type, "unknown")
    unless PolicyRule::SUBJECT_TYPES.include?(type)
      return { subject_type: type, position: 0 }
    end

    case type
    when "role"
      { subject_type: type, subject_value: params[:subject_value].to_s.strip, position: next_position }
    when "any"
      { subject_type: type, position: next_position }
    else
      subject = subject_entity(type, params[:subject_id])
      if subject.nil?
        if params[:subject_id].present?
          return { subject_type: type, subject_id: nil, subject_value: "not_found" }
        else
          return { subject_type: type, subject_id: nil, subject_value: "" }
        end
      end

      { subject_type: type, subject_id: subject.id, position: next_position }
    end
  end

  # A picked subject must be a row in THIS zone; a subject id from another
  # zone (or a missing row) is not a rule target.
  # max + 1, not count + 1: after a removal count + 1 collides with the unique (application, position).
  def next_position
    @application.policy_rules.maximum(:position).to_i + 1
  end

  def subject_entity(type, id)
    klass = PolicyRule::SUBJECT_CLASS[type]
    return nil unless klass && id.to_s.present?

    Object.const_get(klass).where(id: id).joins(:zone).where(zones: { id: @zone.id }).first
  end
end
