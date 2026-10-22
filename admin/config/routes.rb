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

  resources :users, only: %i[index show new create edit update] do
    member do
      post :revoke
    end
  end

  # Slice 7a: read side only (index/show). new_group_path points at the 7b
  # form; until 7b lands the button renders the href via a plain path.
  resources :groups, only: %i[index show]

  get "zone", to: "zone#show", as: :zone
  post "zone/publish", to: "zone#publish", as: :zone_publish
  post "zone/reconcile", to: "zone#reconcile", as: :zone_reconcile

  root "dashboard#show"
end
