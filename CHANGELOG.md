# Change Log

All notable changes to the OmniProbe Scanner project will be documented in this file.

## [v1.2.0] - 2026-02-03

### Added
- **Adaptive Scanning (Specialized Scans)**:
    - Automatically detects technologies (e.g., WordPress).
    - Offers specialized deep scans (e.g., `wpprobe`) directly from the report view.
    - Deep scan results are dynamically appended to the main report.
- **Deep WordPress Scan Integration**:
    - Integrated `wpprobe` tool for stealthy plugin enumeration.
    - Added UI notification upon completion of deep scans (e.g., "Found 1 new finding").
- **UI Improvements**:
    - **Hash Routing**: Implemented custom hash routing (`#/report/:id`) to prevent page refreshes from resetting the app state.
    - **Direct Link Support**: Reports can now be accessed directly via URL.
    - **Print Optimization**: Hided interactive elements (notifications, buttons) from PDF exports for cleaner reports.
    - **Action Status**: Added "In Progress" and "Completed" states for specialized actions.

### Fixed
- **Critical: Blank Page on Report Load**:
    - Fixed a crash in `ReportView.jsx` caused by undefined state variables (`actionResultMsg`).
    - Fixed application redirection to Home on page reload by implementing state restoration from URL hash.
- **Critical: Scan Button Stuck**:
    - Fixed an issue where the backend server reload (due to file changes) cleared in-memory scan state, causing the UI to hang.
- **Tooling**:
    - Corrected `wpprobe` command syntax in backend execution.
    - Fixed `wpprobe` installation in `install.sh`.

## [v1.1.0] - 2026-02-01

### Added
- **Multi-Tool Support**: Integrated Httpx, Katana, and Nuclei into a unified pipeline.
- **Installation Script**: Created `install.sh` for automated dependency management (macOS/Linux).
- **Report Export**: Added PDF export functionality.
- **Live Logs**: Real-time log streaming from backend to frontend.

### Changed
- **Pipeline Optimization**: Tuned scan timeouts and thread counts for better performance.
- **UI Redesign**: Moved to a dark-themed, cyber-aesthetic interface using Tailwind CSS.
