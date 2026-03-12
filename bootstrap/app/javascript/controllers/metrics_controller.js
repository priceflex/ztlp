import { Controller } from "@hotwired/stimulus"

// Formats and displays metric values with visual indicators
export default class extends Controller {
  static targets = ["uptime", "value"]

  connect() {
    this.formatUptimes()
    this.addSparklineIndicators()
  }

  formatUptimes() {
    if (this.hasUptimeTarget) {
      this.uptimeTargets.forEach(el => {
        const seconds = parseInt(el.dataset.value)
        if (!isNaN(seconds)) {
          el.textContent = this.formatDuration(seconds)
        }
      })
    }
  }

  formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`
    if (seconds < 3600) {
      const m = Math.floor(seconds / 60)
      const s = seconds % 60
      return `${m}m ${s}s`
    }
    if (seconds < 86400) {
      const h = Math.floor(seconds / 3600)
      const m = Math.floor((seconds % 3600) / 60)
      return `${h}h ${m}m`
    }
    const d = Math.floor(seconds / 86400)
    const h = Math.floor((seconds % 86400) / 3600)
    return `${d}d ${h}h`
  }

  addSparklineIndicators() {
    // Add simple color-coded indicators for metric values
    this.element.querySelectorAll("[data-metric-threshold]").forEach(el => {
      const value = parseFloat(el.textContent)
      const threshold = parseFloat(el.dataset.metricThreshold)
      const warningThreshold = parseFloat(el.dataset.metricWarning) || threshold * 0.8

      if (value >= threshold) {
        el.classList.add("text-red-600", "font-bold")
      } else if (value >= warningThreshold) {
        el.classList.add("text-yellow-600", "font-semibold")
      } else {
        el.classList.add("text-green-600")
      }
    })
  }
}
