class DocsController < ApplicationController
  VALID_PAGES = %w[overview networks machines users devices groups enrollment deployment].freeze

  def index
  end

  def show
    @page = params[:page]
    if VALID_PAGES.include?(@page)
      render template: "docs/#{@page}"
    else
      redirect_to docs_path, alert: "Documentation page not found."
    end
  end
end
