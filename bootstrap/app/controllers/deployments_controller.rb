class DeploymentsController < ApplicationController
  def index
    @deployments = Deployment.recent.includes(machine: :network).limit(50)
  end

  def show
    @deployment = Deployment.find(params[:id])
  end
end
