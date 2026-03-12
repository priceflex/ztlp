import { Controller } from "@hotwired/stimulus"

// Manages alert interactions: acknowledge, filter by severity
export default class extends Controller {
  static targets = ["filters"]

  acknowledge(event) {
    // The acknowledge action is handled by the form/link POST
    // This controller can add UI feedback if needed
    const button = event.currentTarget
    button.textContent = "Acknowledging..."
    button.classList.add("opacity-50")
  }

  filterBySeverity(event) {
    const severity = event.currentTarget.dataset.severity
    const url = new URL(window.location.href)
    if (severity) {
      url.searchParams.set("severity", severity)
    } else {
      url.searchParams.delete("severity")
    }
    Turbo.visit(url.toString())
  }

  filterByStatus(event) {
    const status = event.currentTarget.dataset.status
    const url = new URL(window.location.href)
    if (status) {
      url.searchParams.set("status", status)
    } else {
      url.searchParams.delete("status")
    }
    Turbo.visit(url.toString())
  }
}
