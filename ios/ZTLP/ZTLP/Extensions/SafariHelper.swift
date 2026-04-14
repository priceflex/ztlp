import SwiftUI
import WebKit

/// In-app web browser using WKWebView.
/// Unlike SFSafariViewController, WKWebView runs in the app's process
/// and respects the VPN tunnel's split-DNS routing for *.ztlp resolution.
struct InAppBrowserView: UIViewControllerRepresentable {
    let url: URL

    func makeUIViewController(context: Context) -> BrowserViewController {
        let vc = BrowserViewController(url: url)
        return vc
    }

    func updateUIViewController(_ uiViewController: BrowserViewController, context: Context) {}
}

class BrowserViewController: UIViewController, WKNavigationDelegate {
    private let url: URL
    private var webView: WKWebView!
    private var progressView: UIProgressView!

    init(url: URL) {
        self.url = url
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        // Progress bar at top
        progressView = UIProgressView(progressViewStyle: .default)
        progressView.tintColor = UIColor(red: 0.0, green: 0.48, blue: 0.98, alpha: 1.0)
        view.addSubview(progressView)
        progressView.translatesAutoresizingMaskIntoConstraints = false

        // WKWebView
        let config = WKWebViewConfiguration()

        webView = WKWebView(frame: .zero, configuration: config)
        webView.navigationDelegate = self
        webView.allowsBackForwardNavigationGestures = true
        view.addSubview(webView)
        webView.translatesAutoresizingMaskIntoConstraints = false

        NSLayoutConstraint.activate([
            progressView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            webView.topAnchor.constraint(equalTo: progressView.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        // Load the URL
        webView.load(URLRequest(url: url))
        progressView.progress = 0
        progressView.alpha = 1

        // Observe loading progress
        webView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
    }

    override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == #keyPath(WKWebView.estimatedProgress), let wv = object as? WKWebView {
            progressView.progress = Float(wv.estimatedProgress)
            if wv.estimatedProgress >= 1.0 {
                UIView.animate(withDuration: 0.3, delay: 0.3) {
                    self.progressView.alpha = 0
                }
            }
        }
    }

    deinit {
        webView.removeObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress))
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        progressView.alpha = 0
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        progressView.alpha = 0
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        progressView.alpha = 0
    }
}

private struct BrowserSheetModifier: ViewModifier {
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
                InAppBrowserView(url: url)
                    .ignoresSafeArea()
            }
        }
    }
}

extension View {
    func safariSheet(url: Binding<URL?>) -> some View {
        modifier(BrowserSheetModifier(url: url))
    }
}
