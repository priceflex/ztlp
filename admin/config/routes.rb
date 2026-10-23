# frozen_string_literal: true

Rails.application.routes.draw do
  get "up", to: "health#up"

  get  "claim",  to: "claims#show"
  post "claim",  to: "claims#create"

  get    "login",  to: "sessions#new"
  delete "logout", to: "sessions#destroy"
  post   "auth/challenge", to: "sessions#challenge"
  post   "auth/verify",    to: "sessions#verify"
  get    "auth/session/:token", to: "sessions#exchange", as: :auth_session

  resources :admins, only: %i[index new create edit update]
  resources :audit_logs, only: [ :index ]

  # Slice 9b sub-slice 2 (read) + sub-slice 3 (new/create, edit/update) +
  # sub-slice 4 (policy-rule add/remove, handled by ApplicationRulesController).
  resources :applications, only: %i[index show new create edit update] do
    scope module: nil do
      resource :rules, only: %i[create], controller: "application_rules", as: :rules
      resources :rules, only: %i[destroy], controller: "application_rules"
    end
  end

  resources :users, only: %i[index show new create edit update] do
    member do
      post :revoke
    end
  end

  # Slice 8: Devices directory (read side 8a; revoke 8b; assign_owner 8c).
  resources :devices, only: %i[index show] do
    member do
      post :revoke
      post :assign_owner
    end
  end

  # Slice 7a read side + 7b mutations (new/create, edit/update, destroy,
  # add_member/remove_member).
  resources :groups do
    member do
      post :add_member
      delete :remove_member
    end
  end

  get "zone", to: "zone#show", as: :zone
  post "zone/publish", to: "zone#publish", as: :zone_publish
  post "zone/reconcile", to: "zone#reconcile", as: :zone_reconcile

  root "dashboard#show"
end
