// LogsViewModel.swift
// ZTLP
//
// ViewModel for the Logs tab. Loads entries from TunnelLogger,
// observes real-time log notifications, and provides filtering.

import Foundation
import Combine

/// ViewModel for the log viewer.
@MainActor
final class LogsViewModel: ObservableObject {

    // MARK: - Published State

    /// All log entries loaded from the file.
    @Published var entries: [LogEntry] = []

    /// Filter to a specific log level (nil = show all).
    @Published var filterLevel: LogLevel? = nil

    /// Text search filter.
    @Published var searchText: String = ""

    /// Upload-related entries shown in the phone logs status section.
    @Published var uploadEntries: [LogEntry] = []

    // MARK: - Computed

    /// Entries after applying level and text filters.
    var filteredEntries: [LogEntry] {
        entries.filter { entry in
            // Level filter
            if let level = filterLevel, entry.level != level {
                return false
            }
            // Text search
            if !searchText.isEmpty {
                let query = searchText.lowercased()
                return entry.message.lowercased().contains(query)
                    || entry.source.lowercased().contains(query)
                    || entry.level.rawValue.lowercased().contains(query)
            }
            return true
        }
    }

    // MARK: - Private

    private let logger = TunnelLogger.shared
    private let uploadSources: Set<String> = ["BenchUpload"]
    private let uploadKeywords = ["submitted to bootstrap", "benchmark upload", "benchmark report"]
    private var cancellable: AnyCancellable?

    // MARK: - Init

    init() {
        // Load existing entries
        refresh()

        // Observe new log entries in real time
        cancellable = NotificationCenter.default.publisher(
            for: TunnelLogger.didLog
        )
        .receive(on: DispatchQueue.main)
        .sink { [weak self] notification in
            guard let self = self,
                  let entry = notification.object as? LogEntry else { return }
            self.entries.append(entry)
            if self.isUploadEntry(entry) {
                self.uploadEntries.append(entry)
            }
        }
    }

    // MARK: - Actions

    /// Reload all entries from the log file.
    func refresh() {
        entries = logger.readAll()
        refreshUploadEntries()
    }

    /// Clear all logs.
    func clear() {
        logger.clear()
        entries = []
        uploadEntries = []
    }

    /// Export all logs as UTF-8 data.
    func exportData() -> Data {
        logger.exportData()
    }

    private func refreshUploadEntries() {
        uploadEntries = entries.filter(isUploadEntry)
    }

    private func isUploadEntry(_ entry: LogEntry) -> Bool {
        if uploadSources.contains(entry.source) {
            return true
        }
        let message = entry.message.lowercased()
        return uploadKeywords.contains { message.contains($0) }
    }
}
