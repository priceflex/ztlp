# frozen_string_literal: true

class RenameBenchmarkErrorsToErrorDetails < ActiveRecord::Migration[7.1]
  def change
    rename_column :benchmarks, :errors, :error_details
  end
end
