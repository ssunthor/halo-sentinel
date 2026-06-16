export const GUIDE_VERSION = '2026.06.16';
export const GUIDE_TITLE = 'Defense Halo Customer CVE Analyzer';
export const GUIDE_SUBTITLE = 'User Guide';

// Block types:
//   { type: 'p',        text }
//   { type: 'h3',       text }
//   { type: 'ul',       items[] }
//   { type: 'ol',       items[] }
//   { type: 'tip',      label, text }
//   { type: 'table',    headers[], rows[][] }

export const SECTIONS = [
  {
    id: 'overview',
    title: 'Overview',
    blocks: [
      {
        type: 'p',
        text: 'The Defense Halo Customer CVE Analyzer is a multi-tenant security intelligence platform designed for managed service providers (MSPs) and enterprise security teams. It continuously monitors your client estate for known software vulnerabilities (CVEs), ranks clients by risk exposure, delivers AI-powered remediation guidance, and sends automated email reports to stakeholders.',
      },
      {
        type: 'h3',
        text: 'Key Capabilities',
      },
      {
        type: 'ul',
        items: [
          'Automated CVE scanning sourced from NetBox (CMDB) device and VM inventory',
          'Real-time vulnerability scoring using NIST NVD CVSS data',
          'Recommended software version extraction — the minimum safe version that closes all known CVEs for a device',
          'AI-powered risk analysis and remediation summaries per device and per tenant',
          'Multi-tenant leaderboard with estate-wide aggregated statistics',
          'Scheduled email reports with WYSIWYG-composed preambles and Excel attachments',
          'Excel export of device vulnerability data per tenant',
          'Persistent storage — scan results survive service restarts',
        ],
      },
      {
        type: 'h3',
        text: 'Data Sources',
      },
      {
        type: 'table',
        headers: ['Source', 'What It Provides'],
        rows: [
          ['NetBox (CMDB)', 'Device inventory, VM inventory, OS/platform version, tenant assignment'],
          ['NIST NVD API', 'CVE records, CVSS scores, affected version ranges (CPE data)'],
          ['AI / LLM Endpoint', 'Human-readable risk summaries and remediation recommendations'],
        ],
      },
      {
        type: 'tip',
        label: 'Note',
        text: 'All scan data is cached to disk and persists across restarts. Only new or changed devices are re-queried against NVD on subsequent scans.',
      },
    ],
  },

  {
    id: 'navigation',
    title: 'Navigation',
    blocks: [
      {
        type: 'p',
        text: 'The application has a persistent navigation bar at the top of every page. All primary functions are accessible from this bar.',
      },
      {
        type: 'h3',
        text: 'Navigation Bar Elements',
      },
      {
        type: 'table',
        headers: ['Element', 'Action'],
        rows: [
          ['Shield logo / "DEFENSE HALO"', 'Returns to the Estate Leaderboard (home view)'],
          ["What's New (scroll icon)", 'Opens the application changelog — feature releases and fixes'],
          ['User Guide (book icon)', 'Opens this user guide'],
          ['Scan All Tenants (button)', 'Initiates a global CVE scan of all tenants in the estate'],
          ['Tenant selector (dropdown)', 'Search and select a specific client to open their Tenant Detail view'],
          ['Settings (gear icon)', 'Opens the Settings page for configuring email notifications'],
        ],
      },
      {
        type: 'h3',
        text: 'Application Pages',
      },
      {
        type: 'ul',
        items: [
          'Estate Leaderboard — default view; shows estate-wide stats and ranked client list',
          'Tenant Detail — per-client device list, CVE data, and AI analysis; opened by selecting a tenant',
          'Settings — notification and email configuration',
          'User Guide — this document',
        ],
      },
      {
        type: 'tip',
        label: 'Tip',
        text: 'Clicking the shield logo or "DEFENSE HALO" text in the top-left corner always returns you to the Estate Leaderboard from any page.',
      },
    ],
  },

  {
    id: 'leaderboard',
    title: 'Estate Leaderboard',
    blocks: [
      {
        type: 'p',
        text: 'The Estate Leaderboard is the home view. It provides a real-time summary of your entire managed estate and ranks clients by their peak vulnerability score.',
      },
      {
        type: 'h3',
        text: 'Estate Summary Statistics',
      },
      {
        type: 'p',
        text: 'Six key metrics are displayed in the header stat row:',
      },
      {
        type: 'table',
        headers: ['Metric', 'Description'],
        rows: [
          ['Total Clients', 'Number of tenants in the estate with scan data'],
          ['Devices Scanned', 'Total physical devices and VMs assessed across all tenants'],
          ['Total Vulnerabilities', 'Cumulative count of CVE findings across the estate'],
          ['Critical', 'Devices with at least one CVE scored 9.0 or above'],
          ['High', 'Devices with at least one CVE scored 7.0–8.9'],
          ['Peak Score', 'Highest individual CVE score found anywhere in the estate'],
        ],
      },
      {
        type: 'h3',
        text: 'AI Analysis Engine',
      },
      {
        type: 'p',
        text: 'The AI Analysis Engine panel (right side of the leaderboard header) shows the status of the LLM worker. It processes devices in a queue, generating plain-English risk summaries and remediation recommendations. Status indicators show how many devices are pending analysis, actively being processed, and completed.',
      },
      {
        type: 'h3',
        text: 'Client Table',
      },
      {
        type: 'p',
        text: 'The main table lists every client with scan data, sorted by peak CVE score (highest first). Each row shows:',
      },
      {
        type: 'ul',
        items: [
          'Tenant name',
          'Number of devices scanned',
          'Total CVE count',
          'Count of Critical and High severity findings',
          'Peak score (the single highest CVSS score in that tenant)',
          'Scan age — how long ago the most recent scan completed',
          'A color-coded severity badge',
        ],
      },
      {
        type: 'tip',
        label: 'Tip',
        text: 'Click any row in the client table to open the Tenant Detail view for that client. Use the search box (top of table) to filter by tenant name.',
      },
    ],
  },

  {
    id: 'scanning',
    title: 'Running Scans',
    blocks: [
      {
        type: 'p',
        text: 'Scans are initiated manually. The application does not run scans on an automated schedule. Two scan modes are available: a global scan of all tenants, and a per-tenant scan from within the Tenant Detail view.',
      },
      {
        type: 'h3',
        text: 'Global Scan (All Tenants)',
      },
      {
        type: 'ol',
        items: [
          'Click the "Scan All Tenants" button in the navigation bar.',
          'A scan progress panel appears below the nav bar, showing live status for each phase.',
          'The scan proceeds in three phases: (1) Inventory pull from NetBox, (2) CVE lookup against NIST NVD, (3) Results saved to the local database.',
          'AI analysis of newly discovered devices is queued automatically and runs as a background job after the scan completes.',
          'When finished, the leaderboard refreshes automatically.',
        ],
      },
      {
        type: 'h3',
        text: 'Per-Tenant Scan',
      },
      {
        type: 'ol',
        items: [
          'Open a Tenant Detail view by selecting a tenant from the dropdown or clicking a client row in the leaderboard.',
          'Click the "Scan" button in the tenant detail header.',
          'Only that tenant\'s devices are re-queried; other tenants are unaffected.',
        ],
      },
      {
        type: 'h3',
        text: 'How Scans Work',
      },
      {
        type: 'ul',
        items: [
          'NetBox is queried via its REST API for all devices and VMs assigned to each tenant.',
          'Each device\'s platform/OS version is used to query the NVD CVE API.',
          'Devices sharing the same platform string share a single NVD query (deduplication) — large estates with many identical OS versions scan significantly faster.',
          'NVD results are cached to disk. If a platform string was recently queried, the cached result is reused rather than re-querying NVD.',
          'AI analysis (LLM risk summaries) is generated per device and cached — devices whose CVE data has not changed are not re-analyzed.',
        ],
      },
      {
        type: 'tip',
        label: 'Note',
        text: 'Scan duration depends on the size of the estate and how many unique platform strings are present. A large estate with diverse OS versions may take several minutes on first scan; subsequent scans are much faster due to caching.',
      },
    ],
  },

  {
    id: 'tenant-detail',
    title: 'Tenant Detail View',
    blocks: [
      {
        type: 'p',
        text: 'The Tenant Detail view shows all devices and VMs for a specific client, along with their individual CVE findings and AI-generated risk analysis.',
      },
      {
        type: 'h3',
        text: 'Accessing Tenant Detail',
      },
      {
        type: 'ul',
        items: [
          'Click any row in the Estate Leaderboard client table, or',
          'Select a tenant from the "Select Client" dropdown in the navigation bar.',
        ],
      },
      {
        type: 'h3',
        text: 'Tenant Summary Header',
      },
      {
        type: 'p',
        text: 'The top of the Tenant Detail view displays a summary row for that client: total devices scanned, total CVE count, critical and high device counts, peak score, and scan age. A "Scan" button allows you to re-scan just this tenant.',
      },
      {
        type: 'h3',
        text: 'Filter Controls',
      },
      {
        type: 'table',
        headers: ['Control', 'Function'],
        rows: [
          ['Search box', 'Filter devices by name (case-insensitive substring match)'],
          ['"Unknown" toggle', 'Show or hide devices where the OS/platform could not be determined'],
          ['"VMs only" toggle', 'Restrict the list to virtual machines only (hides physical devices)'],
          ['Pagination controls', 'Navigate through pages when the device count exceeds the page size'],
        ],
      },
      {
        type: 'h3',
        text: 'Device List',
      },
      {
        type: 'p',
        text: 'Each device row displays the device name, device type/role, current OS version, and its peak CVE score. A left-border color indicates severity at a glance:',
      },
      {
        type: 'table',
        headers: ['Border Color', 'Severity', 'Score Range'],
        rows: [
          ['Red', 'Critical', '9.0 – 10.0'],
          ['Orange', 'High', '7.0 – 8.9'],
          ['Yellow', 'Medium', '4.0 – 6.9'],
          ['Blue', 'Low', '0.1 – 3.9'],
          ['Gray', 'None / Unknown', '0.0 or no data'],
        ],
      },
      {
        type: 'p',
        text: 'If a recommended safe version is available, it is displayed below the current OS version in amber (orange-yellow), formatted as "→ x.x.x".',
      },
      {
        type: 'h3',
        text: 'Device Detail Modal',
      },
      {
        type: 'p',
        text: 'Click any device row to open the Device Detail modal. This modal contains:',
      },
      {
        type: 'ul',
        items: [
          'Device metadata: name, type, role, OS version, recommended version (if available)',
          'Full CVE list: each CVE ID, CVSS score, severity level, and brief description',
          'AI Analysis panel: an LLM-generated risk summary and remediation recommendations specific to this device',
          'Export button: downloads an Excel (.xlsx) file with the full CVE list for this device',
        ],
      },
      {
        type: 'tip',
        label: 'Tip',
        text: 'If the AI Analysis panel shows "Pending" or "Analyzing…", the LLM worker has not yet processed this device. It will update automatically as the background worker progresses through the queue.',
      },
    ],
  },

  {
    id: 'cve-scores',
    title: 'CVE Scores & Recommended Versions',
    blocks: [
      {
        type: 'h3',
        text: 'CVSS Scoring',
      },
      {
        type: 'p',
        text: 'Vulnerability severity is expressed using the CVSS (Common Vulnerability Scoring System) v3 scale, ranging from 0.0 (no impact) to 10.0 (maximum severity). Scores are sourced directly from the NIST National Vulnerability Database (NVD).',
      },
      {
        type: 'table',
        headers: ['Severity', 'Score Range', 'Meaning'],
        rows: [
          ['Critical', '9.0 – 10.0', 'Remotely exploitable with high impact; patch immediately'],
          ['High', '7.0 – 8.9', 'Significant risk; prioritize patching in next maintenance window'],
          ['Medium', '4.0 – 6.9', 'Moderate risk; schedule patching'],
          ['Low', '0.1 – 3.9', 'Minimal risk; patch at next opportunity'],
          ['None', '0.0', 'No measurable impact'],
        ],
      },
      {
        type: 'p',
        text: 'The score shown on a device row represents the highest (peak) CVSS score among all CVEs found for that device. A device with 50 low-severity CVEs and one critical CVE will display the critical score.',
      },
      {
        type: 'h3',
        text: 'Recommended Version',
      },
      {
        type: 'p',
        text: 'The recommended version is the minimum software version at which all known CVEs for a device are closed. It is derived from NVD CPE (Common Platform Enumeration) configuration data — specifically the "versionEndExcluding" field, which NVD uses to indicate the first version that is no longer vulnerable.',
      },
      {
        type: 'p',
        text: 'When a device has multiple CVEs, the recommended version is the semantic maximum across all CVEs — in other words, the version that closes every known vulnerability simultaneously.',
      },
      {
        type: 'h3',
        text: 'Limitations',
      },
      {
        type: 'ul',
        items: [
          'Not all CVE records in NVD include structured CPE version data. CVEs that lack this data are excluded from the recommended version calculation.',
          'The recommended version reflects the minimum version to close currently known CVEs. New CVEs may be published for higher versions after a scan.',
          'The recommended version is based on platform string matching between NetBox and NVD. If a device\'s OS/platform string in NetBox does not closely match NVD CPE data, a version may not be returned.',
          'This feature does not replace a full patch management program — it provides a data point to inform patching priorities.',
        ],
      },
      {
        type: 'tip',
        label: 'Example',
        text: 'A device running "Cisco IOS 15.2" might have 5 CVEs. CVE-1 requires ≥15.6, CVE-2 requires ≥16.0, CVE-3 requires ≥15.7, CVE-4 requires ≥16.1, CVE-5 has no version data. The recommended version displayed is 16.1 — the highest "versionEndExcluding" across all CVEs with version data.',
      },
    ],
  },

  {
    id: 'notifications',
    title: 'Email Notifications',
    blocks: [
      {
        type: 'p',
        text: 'The Email Notifications feature allows you to configure scheduled reports delivered to one or more recipients. Each report includes a customizable preamble, an estate summary table, and a ranked list of the top 10 most vulnerable clients, with an Excel attachment containing the full dataset.',
      },
      {
        type: 'h3',
        text: 'Creating a Notification',
      },
      {
        type: 'ol',
        items: [
          'Click the gear icon in the navigation bar to open Settings.',
          'Select the "Notifications" tab.',
          'Click "New Notification" to open the notification editor.',
          'Configure all required fields (see below), then click "Save".',
        ],
      },
      {
        type: 'h3',
        text: 'SMTP Configuration',
      },
      {
        type: 'table',
        headers: ['Field', 'Description'],
        rows: [
          ['SMTP Host', 'Hostname or IP address of your outbound mail relay (e.g., smtp.example.com)'],
          ['Port', 'SMTP port — typically 587 (STARTTLS) or 465 (SSL)'],
          ['TLS', 'Enable TLS/SSL encryption for the SMTP connection'],
          ['Username', 'SMTP authentication username (leave blank if relay does not require auth)'],
          ['Password', 'SMTP authentication password'],
        ],
      },
      {
        type: 'h3',
        text: 'Schedule',
      },
      {
        type: 'table',
        headers: ['Setting', 'Options'],
        rows: [
          ['Frequency', 'Daily, Weekly, or Monthly'],
          ['Time (UTC)', 'Hour and minute (UTC) at which the report is sent'],
          ['Day', 'For Weekly: day of week (Mon–Sun). For Monthly: day of month (1–28).'],
        ],
      },
      {
        type: 'h3',
        text: 'Recipients',
      },
      {
        type: 'p',
        text: 'Enter email addresses in the From, To, CC, and BCC fields using the pill-style input. Type an address and press Enter or comma to add it. Click the × on any pill to remove it.',
      },
      {
        type: 'h3',
        text: 'Message Composition',
      },
      {
        type: 'p',
        text: 'The Subject field supports dynamic tokens that are substituted at send time:',
      },
      {
        type: 'table',
        headers: ['Token', 'Replaced With'],
        rows: [
          ['{date}', 'Report date (YYYY-MM-DD)'],
          ['{datetime}', 'Report date and time'],
          ['{total_clients}', 'Number of clients in the estate'],
          ['{vulnerable}', 'Number of clients with at least one CVE'],
          ['{critical}', 'Number of clients with a critical CVE'],
          ['{peak_score}', 'Highest CVSS score in the estate'],
        ],
      },
      {
        type: 'p',
        text: 'The Body Preamble is composed using a full WYSIWYG rich text editor. Supported formatting includes headings (H1–H3), bold, italic, underline, strikethrough, bullet and numbered lists, blockquotes, text alignment, hyperlinks, and inline images (by URL).',
      },
      {
        type: 'h3',
        text: 'Adding Images to the Preamble',
      },
      {
        type: 'ol',
        items: [
          'Click the image icon in the editor toolbar.',
          'Enter the image URL in the URL field.',
          'Select a width preset (25%, 50%, 75%, 100%) or enter a custom width.',
          'Click "Insert Image". The image appears inline in the editor.',
          'To edit an existing image, click on it in the editor and then click the image toolbar button again.',
        ],
      },
      {
        type: 'h3',
        text: 'Testing and Sending',
      },
      {
        type: 'ul',
        items: [
          '"Send Test" button — sends a test email immediately using the current notification configuration without waiting for the schedule.',
          'The test email contains the same content as a scheduled report (preamble + estate summary + top-10 table + Excel attachment).',
          'If the test email fails, an error message is displayed with the SMTP error detail.',
        ],
      },
      {
        type: 'tip',
        label: 'Tip',
        text: 'Always click "Send Test" after creating or editing a notification to confirm delivery before relying on the scheduled send.',
      },
    ],
  },

  {
    id: 'settings',
    title: 'Settings',
    blocks: [
      {
        type: 'p',
        text: 'The Settings page is accessible from the gear icon in the navigation bar. It contains two tabs: General and Notifications.',
      },
      {
        type: 'h3',
        text: 'General Tab',
      },
      {
        type: 'p',
        text: 'The General tab is reserved for future application-wide configuration options.',
      },
      {
        type: 'h3',
        text: 'Notifications Tab',
      },
      {
        type: 'p',
        text: 'The Notifications tab lists all configured email notifications. Each card shows the notification name, enabled/disabled status, schedule summary, recipient count, and the time of the last successful send.',
      },
      {
        type: 'ul',
        items: [
          'Click "Edit" on any card to open that notification\'s configuration form.',
          'Click "Delete" (and confirm) to permanently remove a notification.',
          'Click the enabled/disabled badge toggle (in the edit form) to temporarily disable a notification without deleting it.',
          'Click "New Notification" to create an additional notification — you may have multiple notifications with different schedules and recipient lists.',
        ],
      },
      {
        type: 'tip',
        label: 'Note',
        text: 'Notifications are stored in the application database and persist across restarts. Changes to the schedule take effect at the next scheduler tick (within 60 seconds).',
      },
    ],
  },

  {
    id: 'export',
    title: 'Export & Reporting',
    blocks: [
      {
        type: 'p',
        text: 'Several export options are available throughout the application for sharing vulnerability data with stakeholders.',
      },
      {
        type: 'h3',
        text: 'Excel Export (Device Detail)',
      },
      {
        type: 'p',
        text: 'From the Device Detail modal, click the "Export" or download button to generate an Excel (.xlsx) file containing the full CVE list for that device. Columns include CVE ID, CVSS score, severity, description, and published date.',
      },
      {
        type: 'h3',
        text: 'Email Report Attachment',
      },
      {
        type: 'p',
        text: 'Scheduled email reports (configured in Settings → Notifications) include an Excel attachment with the full estate dataset — all tenants, all devices, all CVEs — at the time the report is sent.',
      },
      {
        type: 'h3',
        text: 'User Guide Export',
      },
      {
        type: 'p',
        text: 'This user guide can be exported in three formats using the buttons at the top of the User Guide page:',
      },
      {
        type: 'table',
        headers: ['Format', 'Description'],
        rows: [
          ['TXT', 'Plain text export — suitable for embedding in wikis, ticketing systems, or email'],
          ['Markdown', 'Formatted markdown (.md) — suitable for Git repositories or documentation platforms'],
          ['PDF', 'Opens a print-optimized version in a new browser tab; use the browser\'s "Save as PDF" option in the print dialog'],
        ],
      },
      {
        type: 'tip',
        label: 'Tip',
        text: 'All exported formats include the complete guide content — not just the currently visible section.',
      },
    ],
  },
];
