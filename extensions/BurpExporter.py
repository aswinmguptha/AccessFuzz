from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import json
import os

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("AccessFuzz Exporter")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu = JMenuItem("Export Endpoints", actionPerformed=lambda x: self.export_endpoints())
        return [menu]

    def export_endpoints(self):
        history = self._callbacks.getProxyHistory()
        results = []

        for item in history:
            request_info = self._helpers.analyzeRequest(item)
            method = request_info.getMethod()
            url = str(request_info.getUrl())

            results.append({
                "method": method,
                "url": url
            })

        json_output = json.dumps(results, indent=2)

        # Copy to clipboard
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(json_output), None)

        # Save to file
        output_path = os.path.join(os.path.expanduser("~"), "endpoints.json")
        with open(output_path, "w") as f:
            f.write(json_output)

        print("[+] Export complete.")
        print("[+] Endpoints copied to clipboard and saved to: {}".format(output_path))
