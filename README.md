<h1 align="center">Black Pearl</h1>

<p align="center">
  Team platform for collecting, crawling, processing, and analysing unstructured intelligence data.
</p>

## About Black Pearl

Black Pearl is an open-source platform to **collect, crawl, process and analyse unstructured data** from the clear web, Tor, I2P, chats, files and external feeds. It helps analysts transform raw, messy content into structured intelligence through extraction, tagging, detection, correlation and investigation workflows.

Black Pearl includes:
- an **extensible Python-based framework** for processing and analysing unstructured information,
- a **crawler manager** for continuous and authenticated collection,
- **feeders** for communication platforms and external streams,
- a **detection and retro-hunt engine** based on keywords, regex and YARA,
- **search, correlation and investigation** capabilities to pivot across extracted data,
- and **export/integration** features for platforms such as [MISP](https://github.com/MISP/MISP).

## Intelligence lifecycle

Black Pearl follows a practical intelligence workflow:

1. **Collection**
   Continuous ingestion from chats, websites, hidden services, files and feeds.
2. **Processing**
   Extraction, decoding, OCR, QR/barcode parsing, enrichment and tagging.
3. **Detection**
   Real-time tracking with words, sets, regex, typo-squatting and YARA rules.
4. **Analysis**
   Search, pivoting, correlation graphs and investigations.
5. **Dissemination**
   Export of findings and objects to MISP intelligence-sharing platforms.

## Platform capabilities

Recent releases significantly expanded search, image analysis, crawling and document-processing capabilities.

Highlights include:

- **Unified search interface** with best-match and most-recent ordering
- **Date range filtering** and improved advanced search workflows
- **Image and screenshot descriptions** for faster visual analysis and searchability
- **Expanded OCR and QR extraction**, including support for more difficult image cases
- **Full PDF processing pipeline**, including metadata extraction and **translation** support
- **I2P crawling support** in addition to clear web and Tor collection
- **Passive SSH correlation** for infrastructure analysis and deanonymization workflows
- **Improved chat exploration** for platforms such as Discord, Telegram and Matrix

## Features

### Collection

- Modular architecture to handle streams of unstructured information
- Multiple feeder and importer support
- Feeders for chat and stream sources such as Discord, Telegram and other providers
- Crawling support for the clear web, darknet, **Tor hidden services** (.onion), and **I2P**
- Authenticated crawling with browser sessions, cookies and local storage reuse
- Continuous or on-demand monitoring of websites and hidden services over time
- UI submission/import capabilities

### Processing and enrichment

- Full-text indexing of unstructured information (chats, crawled contents)
- Extraction of URLs, hostnames, email addresses and credentials
- Detection of phone numbers, API keys, IBANs, certificates and private keys
- Detection of Bitcoin addresses, private keys and related cryptocurrency artifacts
- File extraction and decoding from encoded content (Base64, hex)
- OCR processing for screenshots and images
- QR code and barcode extraction with reprocessing of embedded content
- AI-assisted descriptions for images, screenshots and domains
- PDF metadata extraction, ingestion and translation
- Tagging system using [MISP Galaxy](https://github.com/MISP/misp-galaxy) and [MISP Taxonomies](https://github.com/MISP/misp-taxonomies)

### Detection and tracking

Trackers are user-defined rules or patterns that automatically detect, tag and notify analysts about relevant information collected by Black Pearl.

Supported tracker types:

- word tracking
- set-of-words tracking
- regex tracking
- YARA rules
- typo-squatting detection

Detection capabilities include:

- real-time tagging and classification
- object occurrence tracking
- webhook or email notification workflows
- built-in YARA editor

Black Pearl also supports **Retro Hunts**, enabling analysts to run newly created YARA rules against **historical data** to uncover previously missed content.

![tracker-create](./doc/screenshots/tracker_create.png "Tracker creation")

![tracker-yara](./doc/screenshots/tracker_yara.png "YARA tracker")

![retro-hunt](./doc/screenshots/retro_hunt.png "Retro hunt")

### Search, correlation and investigation

- Unified search interface with recency and relevancy ordering
- Search by date range and specialized advanced search for selected data types
- Search across chats, crawled domains, titles, filenames and AI-generated descriptions
- Correlation engine and graph visualisation for relationships between:
  - decoded files and hashes
  - PGP metadata
  - domains, titles, dom-hash, favicons, cookie-names
  - usernames and user-accounts
  - CVEs
  - SSH keys
  - cryptocurrencies
  - PDF metadata
  - ...
- Investigation workflow to group, enrich and follow analyst findings

![global search](./doc/screenshots/search.png "Global search")

### Export and integrations

- Alerting and sharing to [MISP](https://github.com/MISP/MISP)
- Export of objects and investigations to MISP formats
- Automatic exports on selected detections and tags
- Integrations supporting collaborative intelligence and incident-response workflows

## Why Black Pearl?

Black Pearl is built for analysts who need to work with **messy, real-world data**:

- free text,
- screenshots,
- PDFs and files,
- chat messages,
- encoded payloads,
- content collected from web, Tor and I2P sources.

Instead of treating those sources separately, Black Pearl helps turn them into searchable, correlated and actionable intelligence.

## Screenshots

### Websites, forums and hidden services

![Domain CIRCL](./doc/screenshots/domain_circl.png?raw=true "Crawled domain view")

#### Login-protected crawling with pre-recorded session cookies

![Domain cookiejar](./doc/screenshots/crawler-cookiejar-domain-crawled.png?raw=true "Authenticated crawling")

### Extracted and decoded files

![Extracted files](./doc/screenshots/decodeds_dashboard.png?raw=true "Decoded files dashboard")

### Correlation engine

![Onion Domains Correlations](./doc/screenshots/correlation.png?raw=true "Onion domain correlations")

![Correlation decoded image](./doc/screenshots/correlation_decoded_image.png?raw=true "Decoded image correlations")

### Investigation

![Investigation](./doc/screenshots/investigation_mixer.png?raw=true "Investigation view")

### Tagging system

![Tags](./doc/screenshots/tags_search.png?raw=true "Tags search")

![Tags search](./doc/screenshots/tags_search_items.png?raw=true "Tagged items")

### MISP export

![misp_export](./doc/screenshots/misp_export.png?raw=true "MISP export")

### Automatic events and alerts

![tags_misp_auto](./doc/screenshots/tags_misp_auto.png?raw=true "Automatic MISP export")

### UI submission

![ui_submit](./doc/screenshots/ui_submit.png?raw=true "UI importer")

## Installation

To install Black Pearl:

```bash
# Clone Black Pearl
git clone https://github.com/BurmanHarsh/Deanonymization-Solution.git
cd Deanonymization-Solution
git submodule update --init --recursive

# Install dependencies on Debian/Ubuntu-based distributions
./installing_deps.sh

# Start Black Pearl
cd bin
./LAUNCH.sh -l
```

The default [installing_deps.sh](./installing_deps.sh) script targets Debian and Ubuntu based distributions.

### Requirements

- Python 3.8+

Size the deployment according to the expected volume of collected data, crawlers, and active analysis modules.

### Installation notes


Some optional components require additional configuration, including the **Lacus crawler**, the **Meilisearch search indexer**, and translation. See [HOWTO.md](HOWTO.md) for detailed setup instructions.

## Starting Black Pearl

```bash
cd bin
./LAUNCH.sh -l
```

The web interface is available at:

```text
https://localhost:7000/
```

The default credentials are stored in the `DEFAULT_PASSWORD` file and the file is removed once the password is changed.

## Documentation

- Main documentation: [doc/README.md](doc/README.md)
- API documentation: [doc/api.md](doc/api.md)
- HOWTO guides: [HOWTO.md](HOWTO.md)

## Training


Use the project documentation and HOWTO guides to operate and extend Black Pearl.
## Privacy and GDPR

For information on privacy and GDPR-related considerations, review the applicable laws and policies governing collection, analysis and sharing of information.

Operate Black Pearl lawfully, especially within the scope of the General Data Protection Regulation.

## Funding 🇪🇺 

Black Pearl is maintained as an independent team project.

![EU logo](https://www.vulnerability-lookup.org/images/eu-funded.jpg)

## Disclaimer

Co-funded by the European Union. Views and opinions expressed are however those of the author(s) only and do not necessarily reflect those of the European Union or the European Cybersecurity Competence Centre. Neither the European Union nor the granting authority can be held responsible for them.

## License

```text
Copyright (C) 2014 Jules Debra
Copyright (c) 2021 Olivier Sagit
Copyright (C) 2014-2026 CIRCL - Computer Incident Response Center Luxembourg
Copyright (c) 2014-2024 Raphaël Vinot
Copyright (c) 2014-2026 Alexandre Dulaunoy
Copyright (c) 2016-2024 Sami Mokaddem
Copyright (c) 2018-2026 Thirion Aurélien

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
