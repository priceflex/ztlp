import { Controller } from "@hotwired/stimulus"

// Manages wizard step navigation and zone auto-suggestion.
export default class extends Controller {
  static targets = ["nameInput", "zoneInput", "step"]

  connect() {
    this.currentStep = 0
    this.updateStepVisibility()
  }

  // Navigate to next step
  nextStep() {
    if (this.currentStep < this.stepTargets.length - 1) {
      this.currentStep++
      this.updateStepVisibility()
    }
  }

  // Navigate to previous step
  prevStep() {
    if (this.currentStep > 0) {
      this.currentStep--
      this.updateStepVisibility()
    }
  }

  // Go to a specific step
  goToStep(event) {
    const step = parseInt(event.currentTarget.dataset.step)
    if (!isNaN(step) && step >= 0 && step < this.stepTargets.length) {
      this.currentStep = step
      this.updateStepVisibility()
    }
  }

  updateStepVisibility() {
    this.stepTargets.forEach((el, index) => {
      el.classList.toggle("hidden", index !== this.currentStep)
    })
  }

  // Auto-suggest zone based on network name
  suggestZone() {
    if (!this.hasNameInputTarget || !this.hasZoneInputTarget) return

    const name = this.nameInputTarget.value.trim().toLowerCase()
    if (name.length === 0) return

    // Only suggest if zone is empty or was auto-generated
    const currentZone = this.zoneInputTarget.value
    if (currentZone && !currentZone.endsWith(".ztlp")) return

    const zone = name
      .replace(/[^a-z0-9\-]/g, "-")
      .replace(/-+/g, "-")
      .replace(/^-|-$/g, "")
    this.zoneInputTarget.value = zone ? `${zone}.ztlp` : ""
  }
}
