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

  root "dashboard#show"
end
