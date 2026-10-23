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
    member do
      post :enable
      post :disable
    end
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

  # Slice 9b sub-slice 6: gateway minimal CRUD inline from the application
  # form. Gateways are the objects applications live on, so the inline
  # "New gateway" form is reachable from the application flow.
  get  "apps/new_gateway", to: "gateways#new", as: :new_gateway
  post "gateways", to: "gateways#create", as: :gateways
  post "gateways/:id/update_kind", to: "gateways#update_kind", as: :update_kind_gateway

  # Slice 9c: policies page (read-only overview + Test access widget).
  get "policies", to: "policies#index", as: :policies
  post "policies/test", to: "policies#test", as: :policies_test

  # Slice 10b sub-slice 1: Enrollments page (read side + revoke). Sub-slice 2
  # adds the mint (POST /enrollments → create) and the show-once result page.
  resources :enrollments, only: %i[index show new create], path: "enrollments" do
    member do
      post :revoke
      get :result
    end
  end

  get "zone", to: "zone#show", as: :zone
  post "zone/publish", to: "zone#publish", as: :zone_publish
  post "zone/reconcile", to: "zone#reconcile", as: :zone_reconcile

  # Slice 10b sub-slice 3: the SIGNED machine-to-machine redeem endpoint
  # (spec §7.4). Called over the client's ZTLP tunnel, NOT a browser, so it
  # extends ActionController::Base directly — no tunnel bundle, no admin
  # session. Rate-limited by rack-attack's `api/ip` throttle (10/min/IP,
  # config/initializers/rack_attack.rb).
  scope "api/v1", module: :api do
    post "enrollments/:token_id/redeem", to: "enrollments#redeem", as: :redeem_enrollment
  end

  # Slice 10b sub-slice 4: the LEGACY confirm endpoint (spec §7.4 "Legacy
  # clients"): older clients still call the token's legacy `callback_url`
  # shape — a form POST, unauthenticated, no signed identity. It may NOT
  # enroll: it marks the enrollment `redeemed_unverified` and creates the
  # device as `pending` for an administrator to adopt. Machine-to-machine:
  # extends ActionController::Base directly; rate-limited by the same
  # rack-attack `api/ip` throttle as the signed redeem path.
  post "api/enrollment/confirm", to: "api/enrollment_legacy#confirm", as: :enrollment_confirm # spec §7.4

  root "dashboard#show"
end
