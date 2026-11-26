import Cocoa

class AppDelegate: NSObject, NSApplicationDelegate {
    var statusItem: NSStatusItem!
    let serverURL = "http://127.0.0.1:5055"

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem.button {
            button.title = "🛡️ HIDS"
            button.toolTip = "Host-Based Intrusion Detection System"
        }

        buildMenu()
        
        // Periodic status check timer (every 10s)
        Timer.scheduledTimer(withTimeInterval: 10.0, repeats: true) { [weak self] _ in
            self?.checkStatus()
        }
    }

    func buildMenu(serverRunning: Bool = true) {
        let menu = NSMenu()
        
        let titleItem = NSMenuItem(title: serverRunning ? "🟢 HIDS: Monitoring Active" : "🔴 HIDS: Server Stopped", action: nil, keyEquivalent: "")
        titleItem.isEnabled = false
        menu.addItem(titleItem)
        
        menu.addItem(NSMenuItem.separator())

        let dashItem = NSMenuItem(title: "📊 Open Dashboard", action: #selector(openDashboard), keyEquivalent: "d")
        dashItem.target = self
        menu.addItem(dashItem)

        let alertsItem = NSMenuItem(title: "🚨 View Alerts", action: #selector(openAlerts), keyEquivalent: "a")
        alertsItem.target = self
        menu.addItem(alertsItem)

        let rulesItem = NSMenuItem(title: "🛡️ Detection Rules (SIEM)", action: #selector(openRules), keyEquivalent: "r")
        rulesItem.target = self
        menu.addItem(rulesItem)

        let scanItem = NSMenuItem(title: "🔍 Trigger Quick Scan", action: #selector(triggerScan), keyEquivalent: "s")
        scanItem.target = self
        menu.addItem(scanItem)

        menu.addItem(NSMenuItem.separator())

        let cloudflareItem = NSMenuItem(title: "🌐 Open Public Cloudflare URL", action: #selector(openCloudflare), keyEquivalent: "c")
        cloudflareItem.target = self
        menu.addItem(cloudflareItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "Quit Menu Bar Icon", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu
    }

    func checkStatus() {
        guard let url = URL(string: "\(serverURL)/login") else { return }
        var request = URLRequest(url: url)
        request.timeoutInterval = 2.0
        let task = URLSession.shared.dataTask(with: request) { [weak self] _, response, error in
            DispatchQueue.main.async {
                let isRunning = (error == nil && (response as? HTTPURLResponse)?.statusCode == 200)
                if let button = self?.statusItem.button {
                    button.title = isRunning ? "🛡️ HIDS" : "⚠️ HIDS"
                }
            }
        }
        task.resume()
    }

    @objc func openDashboard() {
        if let url = URL(string: serverURL) {
            NSWorkspace.shared.open(url)
        }
    }

    @objc func openAlerts() {
        if let url = URL(string: "\(serverURL)/alerts") {
            NSWorkspace.shared.open(url)
        }
    }

    @objc func openRules() {
        if let url = URL(string: "\(serverURL)/rules") {
            NSWorkspace.shared.open(url)
        }
    }

    @objc func triggerScan() {
        guard let url = URL(string: "\(serverURL)/scan") else { return }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        URLSession.shared.dataTask(with: request) { _, _, _ in
            DispatchQueue.main.async {
                if let url = URL(string: "\(self.serverURL)/") {
                    NSWorkspace.shared.open(url)
                }
            }
        }.resume()
    }

    @objc func openCloudflare() {
        // Read trycloudflare.com URL from log if present
        let logPath = "/tmp/cloudflared_hids.log"
        if let content = try? String(contentsOfFile: logPath, encoding: .utf8) {
            let pattern = "https://[a-zA-Z0-9.-]+\\.trycloudflare\\.com"
            if let regex = try? NSRegularExpression(pattern: pattern),
               let match = regex.firstMatch(in: content, range: NSRange(content.startIndex..., in: content)),
               let range = Range(match.range, in: content) {
                let cfUrl = String(content[range])
                if let url = URL(string: cfUrl) {
                    NSWorkspace.shared.open(url)
                    return
                }
            }
        }
        // Fallback to local
        openDashboard()
    }

    @objc func quitApp() {
        NSApplication.shared.terminate(self)
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory) // Hides from Dock, lives purely in the menu bar!
let delegate = AppDelegate()
app.delegate = delegate
app.run()
