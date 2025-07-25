# BurpExporter - Burp Suite Extension

A lightweight Burp Suite extension to extract HTTP requests from the Burp Proxy/HTTP history and export them in a structured format compatible with the `AccessFuzz` automated authorization tester.

## Loading Extension 
1. Download [BurpExporter.py](./BurpExporter.py)
2. Open **Burp Suite**.
3. Go to the **Extensions** tab.
4. Navigate to the **Installed** sub-tab.
5. Click **Add**.
6. In the dialog:
   - **Extension type**: Select `Python`.
   - **Extension file**: Browse and select `BurpExporter.py`
7. Click **Next** and **Finish**.
8. The extension will appear in the list and should load without errors.

> ⚠️ If [Jython](https://www.jython.org/) is not configured, download latest version and load it under `Extensions > Extension settings > Python Environment`. 

---

## Exporting Endpoints

Once the extension is loaded, it automatically adds a menu item in the **Burp Suite menu**:

1. Go to Proxy > HTTP History
2. Filter the requests as required
3. Select all filtered requests with `Control + A` and right click on any request
4. Choose `Extensions > AccessFuzz Exporter > Export Endpoints`.
5. The exported data will be copied to the clipboard and saved to a file named `endpoints.json` in the home directory.


### 🧪 Sample Output (clipboard or JSON file)

```json
[
  {
    "method": "GET",
    "url": "http://localhost:5000/api/admin/dashboard"
  },
  {
    "method": "POST",
    "url": "http://localhost:5000/api/user/update"
  }
]