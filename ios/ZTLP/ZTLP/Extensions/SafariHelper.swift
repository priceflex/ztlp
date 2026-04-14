import SwiftUI
import WebKit

/// Maps *.ztlp hostnames to their VIP addresses.
/// Bypasses DNS entirely - the VIP IPs are routed through the tunnel
/// via the NE's includedRoute (10.122.0.0/16).
enum ZTLPServiceVIP {
    static let known: [String: String] = [
        // Vaultwarden
        "vault.ztlp": "10.122.0.4",
        // Primary service (dynamic zone, fallback)
        "primary.ztlp": "10.122.0.2",
        // HTTP proxy
        "http.ztlp": "10.122.0.3",
        // Dynamic zone mappings (common service names)
        "vault.techrockstars.ztlp": "10.122.0.4",
        "techrockstars.ztlp": "10.122.0.2",
    ]

    /// Resolve a hostname to a VIP IP. Returns nil if not a known .ztlp service.
    static func resolve(_ hostname: String) -> String? {
        // Exact match first
        if let vip = known[hostname.lowercased()] {
            return vip
        }
        // Check for *.ztlp pattern and guess VIP based on service prefix
        if hostname.hasSuffix(".ztlp") {
            let parts = hostname.split(separator: ".")
            if parts.count >= 2 {
                let serviceName = parts[0].lowercased()
                // Known service name patterns
                switch serviceName {
                case "vault": return "10.122.0.4"
                case "http", "proxy": return "10.122.0.3"
                default: return "10.122.0.2" // default to primary VIP
                }
            }
        }
        return nil
    }

    /// Convert a URL to use VIP IP if it's a .ztlp service.
    /// Preserves the path but replaces the hostname with the VIP IP.
    /// For HTTP: returns http://VIP_IP/path
    /// For HTTPS: uses HTTP instead (to avoid cert hostname mismatch)
    /// Other schemes: returns the original URL unchanged.
    static func toVIPURL(_ originalURL: URL) -> URL {
        guard
            var components = URLComponents(url: originalURL, resolvingAgainstBaseURL: true),
            let host = components.host,
            let vip = resolve(host)
        else {
            return originalURL
        }

        // Always use HTTP to avoid certificate hostname mismatch with VIP IPs
        components.scheme = "http"
        components.host = vip
        // Port is implicit (80 for http) - but if original was 443 HTTPS,
        // the relay-side VIP handles the routing by destination IP

        return components.url ?? originalURL
    }
}

/// In-app web browser using WKWebView.
/// DNS for *.ztlp is resolved to VIP IPs before loading,
/// so traffic routes through the tunnel via included routes.
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
    private var titleLabel: UILabel!
    private var toolbar: UIToolbar!

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

        // Determine the actual URL to load (resolve *.ztlp to VIP IPs)
        let actualURL = ZTLPServiceVIP.toVIPURL(url)

        // Toolbar at top
        toolbar = UIToolbar()
        toolbar.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(toolbar)

        let doneItem = UIBarButtonItem(
            image: UIImage(systemName: "xmark"),
            style: .done,
            target: self,
            action: #selector(doneTapped)
        )
        let spacer = UIBarButtonItem(barButtonSystemItem: .flexibleSpace, target: nil, action: nil)
        let backItem = UIBarButtonItem(
            image: UIImage(systemName: "chevron.left"),
            style: .plain, target: self, action: #selector(backTapped)
        )
        let forwardItem = UIBarButtonItem(
            image: UIImage(systemName: "chevron.right"),
            style: .plain, target: self, action: #selector(forwardTapped)
        )
        let reloadItem = UIBarButtonItem(
            image: UIImage(systemName: "arrow.clockwise"),
            style: .plain, target: self, action: #selector(reloadTapped)
        )

        // Title label
        titleLabel = UILabel()
        titleLabel.font = .systemFont(ofSize: 14, weight: .medium)
        titleLabel.textColor = .label
        titleLabel.textAlignment = .center
        titleLabel.text = actualURL.host ?? ""
        let titleItem = UIBarButtonItem(customView: titleLabel)

        toolbar.setItems([
            backItem, forwardItem, spacer, titleItem, spacer, reloadItem, doneItem
        ], animated: false)

        // Progress bar
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
            toolbar.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            toolbar.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            toolbar.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            progressView.topAnchor.constraint(equalTo: toolbar.bottomAnchor),
            progressView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            progressView.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            webView.topAnchor.constraint(equalTo: progressView.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            webView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])

        // Load the URL
        if actualURL != url {
            #if DEBUG
            print("[Browser] Rewriting \(url.absoluteString) -> \(actualURL.absoluteString)")
            #endif
        }
        webView.load(URLRequest(url: actualURL))
        progressView.progress = 0
        progressView.alpha = 1

        // Observe loading progress
        webView.addObserver(self, forKeyPath: #keyPath(WKWebView.estimatedProgress), options: .new, context: nil)
    }

    override var prefersStatusBarHidden: Bool { true }

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
        titleLabel.text = webView.title ?? webView.url?.host ?? ""
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        progressView.alpha = 0
        #if DEBUG
        print("[Browser] Failed: \(error.localizedDescription)")
        #endif
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        progressView.alpha = 0
        #if DEBUG
        print("[Browser] ProvFail: \(error.localizedDescription)")
        #endif
    }

    @objc private func doneTapped() {
        // This controller is presented in a sheet, dismiss it
        dismiss(animated: true)
    }

    @objc private func backTapped() {
        if webView.canGoBack { webView.goBack() }
    }

    @objc private func forwardTapped() {
        if webView.canGoForward { webView.goForward() }
    }

    @objc private func reloadTapped() {
        webView.reload()
    }
}

private struct BrowserSheetModifier: ViewModifier {
    @Binding var url: URL?

    func body(content: Content) -> some View {
        content.sheet(
            isPresented: Binding(
                get: { url != nil },
                set: { isPresented in
                    if !isPresented { url = nil }
                }
            )
        ) {
            if let url {
                InAppBrowserView(url: url)
                    .ignoresSafeArea(.all, edges: .bottom)
            }
        }
    }
}

extension View {
    func safariSheet(url: Binding<URL?>) -> some View {
        modifier(BrowserSheetModifier(url: url))
    }
}
