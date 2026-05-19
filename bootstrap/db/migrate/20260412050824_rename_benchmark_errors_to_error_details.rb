# frozen_string_literal: true

class RenameBenchmarkErrorsToErrorDetails < ActiveRecord::Migration[7.1]
  def change
    if column_exists?(:benchmarks, :errors)
      rename_column :benchmarks, :errors, :error_details
    end
  end
end
