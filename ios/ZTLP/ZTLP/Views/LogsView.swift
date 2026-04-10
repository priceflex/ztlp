// LogsView.swift
// ZTLP
//
// Real-time log viewer with level filtering, search, and export.
// Shows logs from both the main app and the Network Extension.

import SwiftUI

struct LogsView: View {
    @StateObject private var viewModel = LogsViewModel()
    @State private var autoScroll = true
    @State private var showExportSheet = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Filter capsules
                filterBar

                // Log entries
                if viewModel.filteredEntries.isEmpty {
                    emptyState
                } else {
                    logList
                }
            }
            .navigationTitle("Logs")
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    Button {
                        autoScroll.toggle()
                    } label: {
                        Image(systemName: autoScroll ? "arrow.down.to.line.compact" : "arrow.down.to.line")
                            .foregroundStyle(autoScroll ? Color.ztlpBlue : .secondary)
                    }
                    .accessibilityLabel(autoScroll ? "Auto-scroll on" : "Auto-scroll off")

                    Menu {
                        Button {
                            showExportSheet = true
                        } label: {
                            Label("Export Logs", systemImage: "square.and.arrow.up")
                        }

                        Button(role: .destructive) {
                            viewModel.clear()
                        } label: {
                            Label("Clear Logs", systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
            }
            .searchable(text: $viewModel.searchText, prompt: "Search logs")
            .sheet(isPresented: $showExportSheet) {
                let data = viewModel.exportData()
                    if let tmpURL = exportToTmpFile(data) {
                        ShareSheet(items: [tmpURL])
                    }
            }
        }
    }

    // MARK: - Filter Bar

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                FilterCapsule(
                    label: "All",
                    isSelected: viewModel.filterLevel == nil
                ) {
                    viewModel.filterLevel = nil
                }

                FilterCapsule(
                    label: "Debug",
                    isSelected: viewModel.filterLevel == .debug,
                    color: .secondary
                ) {
                    viewModel.filterLevel = .debug
                }

                FilterCapsule(
                    label: "Info",
                    isSelected: viewModel.filterLevel == .info,
                    color: Color.ztlpBlue
                ) {
                    viewModel.filterLevel = .info
                }

                FilterCapsule(
                    label: "Warn",
                    isSelected: viewModel.filterLevel == .warn,
                    color: Color.ztlpOrange
                ) {
                    viewModel.filterLevel = .warn
                }

                FilterCapsule(
                    label: "Error",
                    isSelected: viewModel.filterLevel == .error,
                    color: Color.ztlpRed
                ) {
                    viewModel.filterLevel = .error
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
        .background(Color(.systemGroupedBackground))
    }

    // MARK: - Log List

    private var logList: some View {
        ScrollViewReader { proxy in
            List {
                ForEach(Array(viewModel.filteredEntries.enumerated()), id: \.offset) { index, entry in
                    LogEntryRow(entry: entry)
                        .id(index)
                        .listRowInsets(EdgeInsets(top: 4, leading: 12, bottom: 4, trailing: 12))
                }
            }
            .listStyle(.plain)
            .font(.caption.monospaced())
            .onChange(of: viewModel.filteredEntries.count) { _ in
                if autoScroll, let lastIndex = viewModel.filteredEntries.indices.last {
                    withAnimation(.easeOut(duration: 0.2)) {
                        proxy.scrollTo(lastIndex, anchor: .bottom)
                    }
                }
            }
        }
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 16) {
            Spacer()
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)
            Text("No Logs")
                .font(.title3.weight(.semibold))
            Text("Log entries from the app and tunnel\nextension will appear here.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
        }
    }
}

// MARK: - Filter Capsule

private struct FilterCapsule: View {
    let label: String
    let isSelected: Bool
    var color: Color = Color.ztlpBlue
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 14)
                .padding(.vertical, 6)
                .background(
                    isSelected ? color.opacity(0.15) : Color(.tertiarySystemGroupedBackground),
                    in: Capsule()
                )
                .foregroundStyle(isSelected ? color : .secondary)
                .overlay(
                    Capsule()
                        .strokeBorder(isSelected ? color.opacity(0.3) : Color.clear, lineWidth: 1)
                )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Log Entry Row

private struct LogEntryRow: View {
    let entry: LogEntry

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            // Level indicator
            Circle()
                .fill(levelColor)
                .frame(width: 6, height: 6)
                .padding(.top, 5)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(entry.timestamp, style: .time)
                        .font(.caption2)
                        .foregroundStyle(.tertiary)

                    if !entry.source.isEmpty {
                        Text("[\(entry.source)]")
                            .font(.caption2)
                            .foregroundStyle(Color.ztlpBlue.opacity(0.6))
                    }
                }

                Text(entry.message)
                    .font(.caption.monospaced())
                    .foregroundStyle(entry.level == .error ? Color.ztlpRed : .primary)
            }
        }
    }

    private var levelColor: Color {
        switch entry.level {
        case .debug: return .secondary
        case .info:  return Color.ztlpBlue
        case .warn:  return Color.ztlpOrange
        case .error: return Color.ztlpRed
        }
    }
}

// MARK: - Export Helper

private func exportToTmpFile(_ data: Data) -> URL? {
    let tmpDir = FileManager.default.temporaryDirectory
    let url = tmpDir.appendingPathComponent("ztlp-logs-\(Int(Date().timeIntervalSince1970)).txt")
    do {
        try data.write(to: url)
        return url
    } catch {
        return nil
    }
}

// MARK: - Share Sheet

struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ uiViewController: UIActivityViewController, context: Context) {}
}

// MARK: - Preview

#Preview {
    LogsView()
}
