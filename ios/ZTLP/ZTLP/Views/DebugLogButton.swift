import SwiftUI
import UIKit

struct DebugLogButton: View {
    @State private var isPreparing = false
    @State private var showShareSheet = false
    @State private var exportItems: [Any] = []

    var body: some View {
        Button {
            isPreparing = true
            DispatchQueue.main.async {
                if let payload = LogExportService.createExportPayload(reason: "debug_log_button") {
                    exportItems = [payload.fileURL]
                    showShareSheet = true
                }
                isPreparing = false
            }
        } label: {
            HStack(spacing: 8) {
                Image(systemName: "paperplane")
                Text(isPreparing ? "Preparing Logs…" : "Send Logs")
            }
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .disabled(isPreparing)
        .sheet(isPresented: $showShareSheet) {
            ShareSheet(items: exportItems)
        }
    }
}
