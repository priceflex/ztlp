Rails.application.routes.draw do
  root "dashboard#index"

  resources :networks do
    member do
      post :deploy
    end

    resources :machines do
      member do
        post :provision
        post :test_connection
        post :health_check
      end
    end

    resources :tokens, only: [:index, :show, :new, :create] do
      member do
        post :revoke
      end
    end
  end

  resources :deployments, only: [:index, :show]
  resources :audit_logs, only: [:index]

  # Setup Wizard
  get  "wizard",           to: "wizard#new",            as: :wizard_new
  post "wizard/network",   to: "wizard#create_network", as: :wizard_create_network
  get  "wizard/machines",  to: "wizard#machines",       as: :wizard_machines
  post "wizard/machines",  to: "wizard#add_machine",    as: :wizard_add_machine
  delete "wizard/machines/:machine_id", to: "wizard#remove_machine", as: :wizard_remove_machine
  get  "wizard/review",    to: "wizard#review",         as: :wizard_review
  get  "wizard/deploy",    to: "wizard#deploy",         as: :wizard_deploy
  post "wizard/deploy",    to: "wizard#start_deploy",   as: :wizard_start_deploy
  get  "wizard/suggest_zone", to: "wizard#suggest_zone", as: :wizard_suggest_zone

  # Health check endpoint
  get "up" => "rails/health#show", as: :rails_health_check
end
