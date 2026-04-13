import SwiftUI
import SafariServices

struct SafariView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> SFSafariViewController {
        let configuration = SFSafariViewController.Configuration()
        configuration.entersReaderIfAvailable = false

        let controller = SFSafariViewController(url: url, configuration: configuration)
        controller.dismissButtonStyle = .close
        return controller
    }

    func updateUIViewController(_ uiViewController: SFSafariViewController, context: Context) {}
}

private struct SafariSheetModifier: ViewModifier {
    @Binding var url: URL?

    func body(content: Content) -> some View {
        content.sheet(
            isPresented: Binding(
                get: { url != nil },
                set: { isPresented in
                    if !isPresented {
                        url = nil
                    }
                }
            )
        ) {
            if let url {
                SafariView(url: url)
                    .ignoresSafeArea()
            }
        }
    }
}

extension View {
    func safariSheet(url: Binding<URL?>) -> some View {
        modifier(SafariSheetModifier(url: url))
    }
}
