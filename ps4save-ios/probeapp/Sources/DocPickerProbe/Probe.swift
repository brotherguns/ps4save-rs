import UIKit
import UniformTypeIdentifiers

@main
final class ProbeEntry {
    static func main() {
        UIApplicationMain(
            CommandLine.argc,
            CommandLine.unsafeArgv,
            nil,
            "AppDelegate"
        )
    }
}

final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        let win = UIWindow(frame: UIScreen.main.bounds)
        win.rootViewController = LogVC()
        win.makeKeyAndVisible()
        window = win
        return true
    }
}

final class LogVC: UIViewController, UIDocumentPickerDelegate {
    private let logView = UITextView()

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        let stack = UIStackView()
        stack.axis = .vertical
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)

        var items: [(String, Void)] = []
        // (label, action) pairs, mapped below
        _ = items

        func button(_ title: String, _ action: @escaping () -> Void) -> UIButton {
            let b = UIButton(type: .system)
            b.setTitle(title, for: .normal)
            b.setTitleColor(.systemBlue, for: .normal)
            b.backgroundColor = .secondarySystemBackground
            b.layer.cornerRadius = 8
            b.contentEdgeInsets = UIEdgeInsets(top: 12, left: 14, bottom: 12, right: 14)
            b.addAction(UIAction { _ in action() }, for: .touchUpInside)
            return b
        }

        stack.addArrangedSubview(button("folder — Open (in place)  [asCopy=false]") { [weak self] in
            self?.presentPicker([.folder], asCopy: false, label: "folder open-in-place")
        })
        stack.addArrangedSubview(button("folder — Copy  [asCopy=true]") { [weak self] in
            self?.presentPicker([.folder], asCopy: true, label: "folder copy")
        })
        stack.addArrangedSubview(button("file — Open (in place)  [asCopy=false]") { [weak self] in
            self?.presentPicker([.item], asCopy: false, label: "file open-in-place")
        })
        stack.addArrangedSubview(button("file — Copy  [asCopy=true]") { [weak self] in
            self?.presentPicker([.item], asCopy: true, label: "file copy")
        })

        logView.isEditable = false
        logView.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        logView.text = ""
        logView.backgroundColor = .systemBackground
        logView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(logView)

        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor, constant: 12),
            stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            logView.topAnchor.constraint(equalTo: stack.bottomAnchor, constant: 12),
            logView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            logView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            logView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -12),
        ])

        dumpEnvironment()
        append("tap a button; every delegate callback gets logged here.")
    }

    private func presentPicker(_ types: [UTType], asCopy: Bool, label: String) {
        append("--> presenting: \(label)")
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types, asCopy: asCopy)
        picker.delegate = self
        present(picker, animated: true) { [weak self] in
            self?.append("    presented OK (animation completed)")
        }
    }

    func documentPicker(
        _ controller: UIDocumentPickerViewController,
        didPickDocumentsAt urls: [URL]
    ) {
        append("DELEGATE: picks (\(urls.count))")
        for url in urls {
            append("    url: \(url)")
            let ok = url.startAccessingSecurityScopedResource()
            append("    startAccessingSecurityScopedResource: \(ok)")
            if ok {
                append("    isDirectory: \((try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false)")
                url.stopAccessingSecurityScopedResource()
                append("    stopped access")
            }
        }
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        append("DELEGATE: cancelled — picker UI opened and emitted a callback")
    }

    private func append(_ line: String) {
        let main = logView
        DispatchQueue.main.async {
            main.text = (main.text ?? "") + line + "\n"
            let end = NSRange(location: (main.text as NSString).length - 1, length: 0)
            main.scrollRangeToVisible(end)
        }
    }

    private func dumpEnvironment() {
        let info = Bundle.main.infoDictionary ?? [:]
        append("==== ENV DUMP (post-signature Info.plist) ====")
        append("bundle id: \(Bundle.main.bundleIdentifier ?? "?")")
        append("OS: \(UIDevice.current.systemName) \(UIDevice.current.systemVersion)")
        let sceneManifest = info["UIApplicationSceneManifest"]
        append("scene manifest: \(sceneManifest == nil ? "ABSENT (classic)" : "present")")
        info["LSSupportsOpeningDocumentsInPlace"].map { append("LSSupportsOpeningDocumentsInPlace: \($0)") }
            ?? append("LSSupportsOpeningDocumentsInPlace: ABSENT")
        info["UISupportsDocumentBrowser"].map { append("UISupportsDocumentBrowser: \($0)") }
            ?? append("UISupportsDocumentBrowser: ABSENT")
        info["UIFileSharingEnabled"].map { append("UIFileSharingEnabled: \($0)") }
            ?? append("UIFileSharingEnabled: ABSENT")
        if let docs = info["CFBundleDocumentTypes"] as? [[String: Any]], !docs.isEmpty {
            append("CFBundleDocumentTypes: \(docs.count) entries")
            for d in docs {
                let name = d["CFBundleTypeName"] as? String ?? "?"
                let types = (d["LSItemContentTypes"] as? [String]) ?? []
                append("    [\(name)] content types: \(types.joined(separator: ", "))")
            }
        } else {
            append("CFBundleDocumentTypes: ABSENT")
        }
        append("CFBundleDisplayName: \(info["CFBundleDisplayName"] as? String ?? "ABSENT")")
        append("==== end dump ====")
    }
}
