Rails.application.routes.draw do
  root "dashboard#index"

  resources :networks do
    member do
      post :deploy
    end

    # Health monitoring routes
    get :health, to: "health#network_health", as: :health
    post :check_health, to: "health#check_health"

    resources :machines do
      member do
        post :provision
        post :test_connection
        post :health_check
      end

      # Machine health detail
      get :health, on: :member, to: "health#machine_health", as: :health
      post :check_health, on: :member, to: "health#check_machine_health"
    end

    resources :tokens, only: [:index, :show, :new, :create] do
      member do
        post :revoke
      end
    end

    resources :ztlp_users, path: "users"
    resources :ztlp_devices, path: "devices", only: [:index, :show, :destroy]
    resources :ztlp_groups, path: "groups" do
      member do
        post :add_member
        delete :remove_member
      end
    end
    resources :enrollment, only: [:index, :create]
    resources :identity_providers, path: "idp"
  end

  # Self-service enrollment via IdP
  get "networks/:network_id/enroll", to: "idp_enrollment#new", as: :network_enroll

  # OmniAuth callbacks
  get  "/auth/:provider/callback", to: "idp_enrollment#callback"
  post "/auth/:provider/callback", to: "idp_enrollment#callback"
  get  "/auth/failure",            to: "idp_enrollment#failure"

  resources :deployments, only: [:index, :show]
  resources :audit_logs, only: [:index]

  # Alerts
  resources :alerts, only: [:index] do
    member do
      post :acknowledge
    end
    collection do
      post :acknowledge_all
    end
  end

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

  # API endpoints (JSON)
  namespace :api do
    get "networks/:network_id/health", to: "health#network_health", as: :network_health
    get "machines/:id/health", to: "health#machine_health", as: :machine_health
    get "alerts", to: "alerts#index", as: :alerts
  end

  # Documentation
  get "docs", to: "docs#index"
  get "docs/:page", to: "docs#show", as: :doc_page

  # Health check endpoint
  get "up" => "rails/health#show", as: :rails_health_check
end
