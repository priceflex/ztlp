import { Controller } from "@hotwired/stimulus"

// Auto-refreshes health data via Turbo Frames at a configurable interval
export default class extends Controller {
  static targets = ["interval"]

  connect() {
    this.refreshTimer = null
    this.startAutoRefresh()
  }

  disconnect() {
    this.stopAutoRefresh()
  }

  startAutoRefresh() {
    this.stopAutoRefresh()
    const seconds = this.currentInterval()
    if (seconds > 0) {
      this.refreshTimer = setInterval(() => this.refresh(), seconds * 1000)
    }
  }

  stopAutoRefresh() {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer)
      this.refreshTimer = null
    }
  }

  changeInterval() {
    this.startAutoRefresh()
  }

  currentInterval() {
    if (this.hasIntervalTarget) {
      return parseInt(this.intervalTarget.value) || 0
    }
    return 30
  }

  refresh() {
    // Reload Turbo Frames on the page by navigating to the current URL
    const frames = document.querySelectorAll("turbo-frame[src], turbo-frame[data-turbo-frame]")
    if (frames.length > 0) {
      frames.forEach(frame => {
        if (frame.src) {
          frame.reload()
        }
      })
    } else {
      // Fallback: reload the page via Turbo
      Turbo.visit(window.location.href, { action: "replace" })
    }
  }
}
