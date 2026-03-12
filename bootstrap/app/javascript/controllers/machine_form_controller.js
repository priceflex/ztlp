import { Controller } from "@hotwired/stimulus"

// Manages dynamic add/remove machine rows in the wizard.
export default class extends Controller {
  static targets = ["template", "container", "roleCheckbox"]

  connect() {
    this.machineIndex = this.containerTarget ? this.containerTarget.children.length : 0
  }

  // Add a new machine row
  addRow() {
    if (!this.hasTemplateTarget || !this.hasContainerTarget) return

    const content = this.templateTarget.innerHTML.replace(/__INDEX__/g, this.machineIndex)
    const wrapper = document.createElement("div")
    wrapper.innerHTML = content.trim()
    const newRow = wrapper.firstElementChild
    newRow.dataset.machineIndex = this.machineIndex
    this.containerTarget.appendChild(newRow)
    this.machineIndex++

    // Focus the first input in the new row
    const firstInput = newRow.querySelector("input")
    if (firstInput) firstInput.focus()
  }

  // Remove a machine row
  removeRow(event) {
    const row = event.currentTarget.closest("[data-machine-index]")
    if (row) {
      row.remove()
    }
  }

  // Update the hidden roles field from checkboxes
  updateRoles(event) {
    const form = event.currentTarget.closest("form") || this.element
    const checkboxes = form.querySelectorAll("[data-machine-form-target='roleCheckbox']:checked")
    const roles = Array.from(checkboxes).map(cb => cb.value).join(",")
    const rolesInput = form.querySelector("[data-roles-field]")
    if (rolesInput) {
      rolesInput.value = roles
    }
  }
}
