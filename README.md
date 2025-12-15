# VirusTotal Plugin for Binary Ninja

An unofficial Binary Ninja plugin that integrates VirusTotal into reverse engineering and malware analysis workflows.

The plugin allows analysts to launch VirusTotal searches for bytes, code, and functions directly from Binary Ninja.

## Features

* **Search for bytes** Performs a raw byte search in VirusTotal for the selected instruction sequence.
* **Search for similar code** Searches for functionally similar code by wildcarding memory addresses and offsets before querying VirusTotal.

* **Search for similar functions** Automatically detects the boundaries of the current function and searches for similar functions, without requiring manual selection.
* **Automatic sample upload (optional)** On first run, the plugin prompts for consent to upload samples not found on VirusTotal. This behavior can be modified at any time from Binary Ninja settings.

* **Dedicated Strings sidebar** Provides a custom sidebar tab to browse extracted strings and query them directly on VirusTotal.
* **Code Insight (coming soon)**
  Planned integration with VirusTotal Code Insight for AI-assisted analysis.

> **Note**
> VTGrep searches rely on an active VirusTotal Enterprise session in your web browser.

![Code Similarity Search from Binary Ninja](images/vt_search_similar_code.gif)

## Installation

### Recommended: Plugin Manager

The plugin can be installed directly from the Binary Ninja Plugin Manager:

### Manual Installation

1. In Binary Ninja, open:
2. Copy the `vt-binaryninja-plugin` directory into the opened folder.
3. Restart Binary Ninja.

If installing manually, ensure that the `requests` module is available in Binary Ninja’s embedded Python environment.

## Configuration

### First-Time Run

On first execution, the plugin will prompt for consent to upload samples that are not already present on VirusTotal.

- **Ok**: Enable automatic uploads.
- **No**: Disable automatic uploads.
- **Cancel**: Disable the plugin for the current session.

This setting can be changed at any time from Binary Ninja settings.

### API Key Configuration

Your VirusTotal API key can be configured directly inside Binary Ninja:

1. Open **Settings**
2. Navigate to **User → VirusTotal**
3. Enter your API key in the `api_key` field
4. (Optional) Adjust automatic upload settings

All preferences are stored in the Binary Ninja user configuration directory.

## Disclaimer

This is an unofficial, community-maintained plugin and is not affiliated with or endorsed by VirusTotal or Google.
