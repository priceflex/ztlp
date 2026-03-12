import { Controller } from "@hotwired/stimulus"

// Handles deploy log auto-scrolling, expand/collapse per component,
// and ActionCable subscription for live deploy updates.
export default class extends Controller {
  static targets = ["logContainer", "progressBar", "progressText", "statusBadge", "componentCard"]
  static values = { networkId: Number }

  connect() {
    if (this.networkIdValue) {
      this.subscribeToChannel()
    }
    this.autoScrollEnabled = true
  }

  disconnect() {
    if (this.subscription) {
      this.subscription.unsubscribe()
    }
  }

  subscribeToChannel() {
    const controller = this
    // ActionCable consumer is available via Turbo
    if (typeof window.Turbo !== "undefined" && window.Turbo.connectStreamSource) {
      // Using basic ActionCable subscription
    }

    // Get or create ActionCable consumer
    this.ensureConsumer().then(consumer => {
      controller.subscription = consumer.subscriptions.create(
        { channel: "DeployChannel", network_id: controller.networkIdValue },
        {
          received(data) {
            controller.handleMessage(data)
          }
        }
      )
    })
  }

  async ensureConsumer() {
    if (window._actionCableConsumer) return window._actionCableConsumer

    // Dynamic import of actioncable
    const { createConsumer } = await import("@rails/actioncable")
    window._actionCableConsumer = createConsumer()
    return window._actionCableConsumer
  }

  handleMessage(data) {
    switch (data.type) {
      case "status":
        this.handleStatus(data)
        break
      case "progress":
        this.handleProgress(data)
        break
      case "component_status":
        this.handleComponentStatus(data)
        break
      case "log":
        this.handleLogLine(data)
        break
    }
  }

  handleStatus(data) {
    if (this.hasStatusBadgeTarget) {
      this.statusBadgeTarget.textContent = data.message
      if (data.event === "completed") {
        this.statusBadgeTarget.classList.add("text-green-600")
      }
    }
  }

  handleProgress(data) {
    const pct = data.total > 0 ? Math.round((data.completed + data.failed) / data.total * 100) : 0

    if (this.hasProgressBarTarget) {
      this.progressBarTarget.style.width = `${pct}%`
      if (data.failed > 0) {
        this.progressBarTarget.classList.add("bg-red-500")
      }
    }

    if (this.hasProgressTextTarget) {
      this.progressTextTarget.textContent = `${data.completed}/${data.total} completed${data.failed > 0 ? `, ${data.failed} failed` : ""}`
    }
  }

  handleComponentStatus(data) {
    const cardId = `deploy-card-${data.machine_id}-${data.component}`
    const card = document.getElementById(cardId)
    if (!card) return

    // Update status badge
    const badge = card.querySelector("[data-status-badge]")
    if (badge) {
      badge.textContent = data.status
      badge.className = this.statusBadgeClass(data.status)
    }

    // Update message
    const msg = card.querySelector("[data-status-message]")
    if (msg) {
      msg.textContent = data.message
    }
  }

  handleLogLine(data) {
    const logId = `deploy-log-${data.machine_id}-${data.component}`
    const logEl = document.getElementById(logId)
    if (!logEl) return

    const line = document.createElement("div")
    line.className = "text-xs font-mono text-gray-300"
    line.textContent = `[${new Date(data.timestamp).toLocaleTimeString()}] ${data.line}`
    logEl.appendChild(line)

    // Auto-scroll
    if (this.autoScrollEnabled) {
      logEl.scrollTop = logEl.scrollHeight
    }
  }

  // Toggle expand/collapse for a component log
  toggleLog(event) {
    const target = event.currentTarget.dataset.logTarget
    const logEl = document.getElementById(target)
    if (logEl) {
      logEl.classList.toggle("hidden")
      // Toggle arrow icon
      const arrow = event.currentTarget.querySelector("[data-arrow]")
      if (arrow) {
        arrow.classList.toggle("rotate-90")
      }
    }
  }

  // Toggle auto-scroll
  toggleAutoScroll() {
    this.autoScrollEnabled = !this.autoScrollEnabled
  }

  statusBadgeClass(status) {
    const base = "inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium"
    const colors = {
      pending: "bg-yellow-100 text-yellow-800",
      running: "bg-blue-100 text-blue-800",
      success: "bg-green-100 text-green-800",
      failed: "bg-red-100 text-red-800"
    }
    return `${base} ${colors[status] || "bg-gray-100 text-gray-800"}`
  }
}
