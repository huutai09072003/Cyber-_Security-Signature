Rails.application.routes.draw do
  devise_for :models
  resources :files, only: [ :new, :create ]

  # Defines the root path route ("/")
  # root "posts#index"
end
