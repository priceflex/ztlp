// LogsView.swift
// ZTLP
//
// Real-time log viewer with level filtering, search, export, and clear.

import SwiftUI

struct LogsView: View {
    @StateObject private var viewModel = LogsViewModel()
    @State private var autoScroll = true
    @State private var showClearConfirmation = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                // Filter bar
                filterBar

                Divider()

                // Log list
                if viewModel.filteredEntries.isEmpty {
                    emptyState
                } else {
                    logList
                }
            }
            .navigationTitle("Logs")
            .searchable(text: $viewModel.searchText, prompt: "Filter logs…")
            .toolbar {
                ToolbarItemGroup(placement: .topBarTrailing) {
                    // Auto-scroll toggle
                    Button {
                        autoScroll.toggle()
                    } label: {
                        Image(systemName: autoScroll
                              ? "arrow.down.to.line.compact"
                              : "arrow.down.to.line")
                    }
                    .tint(autoScroll ? Color.ztlpBlue : .secondary)
                    .accessibilityLabel(autoScroll ? "Auto-scroll on" : "Auto-scroll off")

                    // Share
                    ShareLink(
                        item: String(data: viewModel.exportData(), encoding: .utf8) ?? "",
                        subject: Text("ZTLP Logs"),
                        message: Text("ZTLP tunnel logs export")
                    ) {
                        Image(systemName: "square.and.arrow.up")
                    }

                    // Clear
                    Button(role: .destructive) {
                        showClearConfirmation = true
                    } label: {
                        Image(systemName: "trash")
                    }
                }
            }
            .confirmationDialog(
                "Clear all logs?",
                isPresented: $showClearConfirmation,
                titleVisibility: .visible
            ) {
                Button("Clear Logs", role: .destructive) {
                    viewModel.clear()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This cannot be undone.")
            }
        }
    }

    // MARK: - Filter Bar

    private var filterBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                FilterCapsule(
                    title: "All",
                    isSelected: viewModel.filterLevel == nil
                ) {
                    viewModel.filterLevel = nil
                }

                ForEach(LogLevel.allCases, id: \.self) { level in
                    FilterCapsule(
                        title: level.rawValue.capitalized,
                        isSelected: viewModel.filterLevel == level,
                        color: level.color
                    ) {
                        viewModel.filterLevel = level
                    }
                }
            }
            .padding(.horizontal)
            .padding(.vertical, 8)
        }
    }

    // MARK: - Log List

    private var logList: some View {
        ScrollViewReader { proxy in
            List(viewModel.filteredEntries) { entry in
                LogEntryRow(entry: entry)
                    .listRowInsets(EdgeInsets(top: 4, leading: 12, bottom: 4, trailing: 12))
                    .id(entry.id)
            }
            .listStyle(.plain)
            .onChange(of: viewModel.filteredEntries.count) { _ in
                if autoScroll, let last = viewModel.filteredEntries.last {
                    withAnimation {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "doc.text.magnifyingglass")
                .font(.system(size: 48))
                .foregroundStyle(.secondary)
            Text("No Logs")
                .font(.title2.weight(.semibold))
                .foregroundStyle(.secondary)
            if viewModel.entries.isEmpty {
                Text("No logs yet. Connect to start logging.")
                    .font(.callout)
                    .foregroundStyle(.tertiary)
            } else {
                Text("No logs match the current filter.")
                    .font(.callout)
                    .foregroundStyle(.tertiary)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - LogEntryRow

private struct LogEntryRow: View {
    let entry: LogEntry

    private static let timeFormatter: DateFormatter = {
        let fmt = DateFormatter()
        fmt.dateFormat = "HH:mm:ss.SSS"
        return fmt
    }()

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack(spacing: 6) {
                // Timestamp
                Text(Self.timeFormatter.string(from: entry.timestamp))
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)

                // Level badge
                Text(entry.level.rawValue)
                    .font(.caption2.bold())
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(entry.level.color.opacity(0.2))
                    .foregroundStyle(entry.level.color)
                    .clipShape(Capsule())

                // Source tag
                Text(entry.source)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Spacer()
            }

            // Message
            Text(entry.message)
                .font(.callout)
                .foregroundStyle(.primary)
                .textSelection(.enabled)
        }
    }
}

// MARK: - FilterCapsule

private struct FilterCapsule: View {
    let title: String
    let isSelected: Bool
    var color: Color = .ztlpBlue
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .background(
                    isSelected ? color.opacity(0.2) : Color(.systemGray5)
                )
                .foregroundStyle(isSelected ? color : .secondary)
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }
}

// MARK: - LogLevel Color Extension

extension LogLevel {
    /// Color associated with each log level.
    var color: Color {
        switch self {
        case .debug: return .gray
        case .info:  return .ztlpBlue
        case .warn:  return .ztlpOrange
        case .error: return .ztlpRed
        }
    }
}

#Preview {
    LogsView()
}
