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

  # Health check endpoint
  get "up" => "rails/health#show", as: :rails_health_check
end
