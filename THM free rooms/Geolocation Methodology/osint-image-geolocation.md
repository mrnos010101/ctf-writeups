# OSINT — Image Geolocation Methodology

> A practical, field-tested methodology for geolocating images during OSINT, red team reconnaissance, and threat intelligence operations.
> Compiled from hands-on practice with TryHackMe "Geolocating Images" room and Bellingcat-style investigation tradecraft.

---

## Table of Contents

1. [Why This Matters for Pentesting & Red Team](#why-this-matters-for-pentesting--red-team)
2. [Two Fundamental Approaches](#two-fundamental-approaches)
3. [Technical Approach — EXIF & Metadata](#technical-approach--exif--metadata)
4. [Visual Approach — Chasing Pixels](#visual-approach--chasing-pixels)
5. [Reverse Image Search Arsenal](#reverse-image-search-arsenal)
6. [The Four Core Techniques](#the-four-core-techniques)
7. [Regional Visual Indicators Cheat Sheet](#regional-visual-indicators-cheat-sheet)
8. [Webcam OSINT — A Separate Discipline](#webcam-osint--a-separate-discipline)
9. [Operational Security During OSINT](#operational-security-during-osint)
10. [Integration into Pentest Workflow](#integration-into-pentest-workflow)
11. [Tooling Quick Reference](#tooling-quick-reference)
12. [Further Reading & Training](#further-reading--training)

---

## Why This Matters for Pentesting & Red Team

Image geolocation is one of the most underrated skills in offensive security. Most CPTS / OSCP+ training tracks treat it as a side topic, but in reality it is a force multiplier across multiple phases of an engagement.

**Pre-engagement reconnaissance.** Photos leaked through employee social media, corporate blogs, news coverage, and conference recaps often reveal more than the target organization realizes — office floor plans, access control hardware models, badge designs, server room layouts, sticker-covered laptops with hostnames and MAC addresses visible. Every public photo of the target is potential intelligence.

**Physical red team operations.** Before any physical compromise attempt, the team needs to understand the perimeter, foot traffic patterns, security guard rotations, and emergency exits. Webcams pointed at or near the target site, geolocated employee photos from break areas, and OSINT-derived imagery of badge styles give the team the data they need to plan an entry.

**Threat intelligence and attribution.** When investigating an APT group, leaked operator photos, propaganda imagery, and infrastructure screenshots become geolocation targets. Bellingcat's investigations of Russian military involvement in Eastern Ukraine and the MH17 incident were largely built on this exact methodology.

**Phishing and social engineering pretext development.** Geolocated photos from corporate events provide authentic-feeling material for pretexts ("I'm reaching out about the team offsite at [specific venue]...").

**Post-engagement reporting.** Recommending an OPSEC audit of the client's public visual footprint is a high-value deliverable that most pentest reports never include.

---

## Two Fundamental Approaches

Image geolocation breaks down into two distinct methodologies that require different mental models.

The **technical approach** treats the image as a data container and extracts machine-readable metadata. This is deterministic — the answer is either in the file or it is not.

The **visual approach** treats the image as evidence to be analyzed and interpreted. This is probabilistic — the analyst builds confidence through multiple converging clues.

A competent analyst applies both approaches in sequence. Start with the technical pass because it is cheap and often produces an immediate answer. If that fails, fall back to the visual pass, which is slower but works on any image regardless of metadata stripping.

---

## Technical Approach — EXIF & Metadata

When a phone or camera takes a photo, it embeds extensive metadata into the file. The most valuable fields for geolocation are GPS coordinates, but device fingerprinting fields also have intelligence value.

### Core Tools

```bash
# Primary tool — most comprehensive
exiftool image.jpg

# Lighter alternative
exiv2 image.jpg

# ImageMagick metadata dump
identify -verbose image.jpg

# Quick GPS coordinate extraction
exiftool -gpslatitude -gpslongitude -gpsaltitude image.jpg

# Strip metadata (useful for OPSEC during ops)
exiftool -all= image.jpg

# Batch process a directory
exiftool -r -gpslatitude -gpslongitude /path/to/images/
```

### Key EXIF Fields for Intelligence

| Field | Intelligence Value |
|-------|-------------------|
| `GPSLatitude` / `GPSLongitude` | Direct coordinates — primary target |
| `GPSAltitude` | Confirms outdoor location, narrows indoor floors in high-rises |
| `DateTimeOriginal` | Cross-reference with sun position, weather records, events |
| `Make` / `Model` | Device fingerprinting — useful for tracking same source across photos |
| `Software` | Editing tool used — indicates technical sophistication of source |
| `Artist` / `Copyright` | Sometimes contains real names of photographers |
| `LensModel` | Specific equipment fingerprint |
| `SerialNumber` | Hardware unique ID — exceptional pivot point |

### Reality Check on EXIF in 2026

Most major social platforms strip EXIF data on upload. Facebook, Instagram, X/Twitter, LinkedIn, and TikTok remove GPS coordinates and most metadata fields. However, the following still typically preserve EXIF:

- Discord (files sent as attachments, not images)
- Telegram (only when sent as "File" rather than as photo)
- Most forum software (phpBB, vBulletin, Discourse with default config)
- Personal websites and blogs
- Email attachments
- Cloud storage links (Google Drive, Dropbox shared files)
- WhatsApp document mode

**OPSEC implication for offensive operations:** when conducting OSINT on a target, always check the original platform's metadata behavior. A target who is OPSEC-aware on Twitter may be careless on Discord.

---

## Visual Approach — Chasing Pixels

When EXIF is stripped, the work shifts to systematic analysis of every visible element in the frame. This is where Bellingcat-style tradecraft lives.

### The Systematic Inventory Method

Before forming any hypothesis, perform a structured inventory of the image. Move through the frame left-to-right, top-to-bottom, foreground-to-background. Catalog every distinguishable element without interpretation. Only after the inventory is complete should you start drawing conclusions.

### Natural Indicators

**Shadow analysis.** The angle and length of shadows reveal both the time of day and the latitude. Combined with the date (from EXIF or contextual clues like vegetation state), shadows can pinpoint geographic latitude within a few degrees.

```
Tools:
- SunCalc (suncalc.org) — interactive sun position calculator
- Stellarium — astronomical software for night sky verification
- Wolfram Alpha — solar position queries
```

**Vegetation.** Tree species indicate climate zones. Coniferous forests, palms, eucalyptus, baobabs — each has a distinct geographic range. Even within a region, deciduous vs evergreen state reveals season.

**Sky and weather.** Cloud formations, sky color, and apparent humidity narrow the climate context.

**Stars.** Night photos with visible stars allow astronomical geolocation. The visible constellations and their angle above the horizon give latitude directly.

### Anthropogenic Indicators

**Road signage.** Each country has standardized sign shapes, colors, and fonts that follow either the Vienna Convention on Road Signs (most of Europe, Africa, Latin America), the MUTCD standard (USA, Canada partially), or unique national standards (UK, Japan, China). A green sign with white text on a US highway looks nothing like a blue Continental European motorway sign.

**License plates.** Format, color scheme, and regional codes narrow location quickly. Russian plates carry a 2- or 3-digit regional code. EU plates carry a country code on the blue strip. US plates vary by state with distinctive designs.

**Architecture.** Building styles, window types, balcony designs, and roofing materials follow regional patterns. Soviet-era panel buildings (Khrushchyovkas, Brezhnevkas) look nothing like American suburban construction or German Altbau.

**Utility infrastructure.** Power line poles, transformer designs, mailbox styles, fire hydrant designs, manhole cover patterns, electrical outlets and plugs — each is regionally distinctive. US uses wooden utility poles; most of Europe uses concrete. UK has type G outlets; Europe uses type C/E/F; Japan uses type A/B.

**Vehicles.** Right-hand vs left-hand drive narrows to a list of countries. Common vehicle models indicate market regions. Taxi designs are often unique (London black cabs, NYC yellow Crown Vics, Bangkok tuk-tuks).

**Language and typography.** Visible text in storefronts, posters, and signage is the highest-confidence indicator. Even when language is recognized, font choices and orthographic conventions can narrow further (simplified vs traditional Chinese, Cyrillic in different Slavic languages).

### Address Grid Systems

Some cities use coordinate-based address grids that can be reverse-engineered without local knowledge. Chicago is the classic example: the grid is anchored at State and Madison streets, with each 800 units representing approximately one mile. A sign reading "3600 N" combined with "1000 W" gives a precise location relative to the city center.

Other grid-based cities include Salt Lake City, Phoenix, and parts of Los Angeles. Learning these systems pays dividends for North American OSINT.

---

## Reverse Image Search Arsenal

No single reverse image search engine is sufficient. Each indexes a different slice of the internet and uses different matching algorithms. Professional practice is to query multiple engines in sequence.

### Primary Engines

**Google Lens** — `https://lens.google.com`
Strongest at object recognition, landmark identification, and product matching. Uses semantic understanding rather than pure pixel matching, which is both its strength and weakness. Best for: identifying buildings, plants, products, recognizable landmarks.

**Yandex Images** — `https://yandex.com/images`
The OSINT community's worst-kept secret. Yandex uses aggressive pixel-level and structural matching algorithms, and indexes Eastern European, Russian, and Asian content far better than Google. Often finds exact matches where Google shows only "similar" results. Best for: facial identification, scene matching, content from Russia/CIS/Eastern Europe/Asia.

**TinEye** — `https://tineye.com`
The original reverse image search, focused on tracking image distribution history rather than semantic understanding. Best for: finding the original source of an image, tracking how a meme variant evolved, identifying recycled stock photos in fake profiles.

**Bing Visual Search** — `https://www.bing.com/visualsearch`
Indexes a different slice of the web than Google. Often returns results others miss. Best for: backup and cross-reference.

### Specialized Tools

| Tool | URL | Use Case |
|------|-----|----------|
| PimEyes | pimeyes.com | Biometric face search across the web (ethically controversial) |
| Karma Decay | karmadecay.com | Reddit-specific reverse image search |
| Berify | berify.com | Aggregated multi-engine search |
| GeoSpy AI | geospy.ai | ML-based geolocation prediction |
| Picarta | picarta.ai | AI location identification |
| Mapillary | mapillary.com | Crowdsourced street-level imagery (Street View alternative) |

### Workflow

A professional reverse image search workflow looks like this:

1. **Strip the image of any obvious metadata that could bias results** — sometimes engines weight EXIF data and serve geographically biased results
2. **Run Google Lens first** for rapid landmark / object identification
3. **Run Yandex Images** especially if first results seem off or content suggests non-Western origin
4. **Run TinEye** if the goal includes tracking the image's distribution history
5. **Cross-reference with Bing** for any unique results
6. **Verify findings against Google Street View / Mapillary** for definitive ground truth

---

## The Four Core Techniques

Through systematic OSINT practice, four reusable techniques emerge that cover most geolocation scenarios.

### Technique 1 — Critical Resistance to First Association

When an image contains a recognizable landmark or object, the brain immediately matches it against memory. This is fast but dangerous. Copies, plagiarized works, lookalike buildings, and chain establishments can all trigger false matches.

**Operational rule:** when a recognition feels "too obvious," slow down and look at the surrounding context. Does the surrounding environment match where the famous object should be? If not, you may be looking at a copy, a replica, or a different instance of the same chain.

*Worked example:* a photo of a giant mirror-polished sculpture resembling Anish Kapoor's Cloud Gate. The first association is Chicago's Millennium Park. But the surrounding environment shows a construction crane, sparse trees, and small accompanying spheres that the original sculpture does not have. This is actually a copy in Karamay, China — a famous case of architectural plagiarism that Anish Kapoor publicly disputed.

### Technique 2 — Textual OSINT Through Environmental Signage

Any readable text in the frame should be the highest priority target for analysis. Text provides deterministic information that can be queried directly against indexed sources, in contrast to visual cues that require probabilistic interpretation.

**Operational rule:** before analyzing any visual feature, scan the entire image for readable text — street signs, storefront names, license plates, posters, badges, document fragments, screen content, sticker labels, building number plates. Each readable element is a potential pivot to direct lookup.

*Worked example:* a night webcam image showing a US-style green street sign reading "N SHEFFIELD AV 1000 W" and "N ADDISON ST 3600 N." Even without recognizing the building, this combination — green-on-white US signage with grid-coordinate format — points uniquely to Chicago's address grid system. The intersection of Sheffield (1000W) and Addison (3600N) is Wrigley Field.

### Technique 3 — Structured Analytic Hypothesis Testing

When visual interpretation yields multiple plausible candidates, the discipline of structured analysis is what separates professional analysts from guessers. Document each hypothesis, list the evidence that supports and contradicts each one, then verify the strongest candidate through external search.

**Operational rule:** when uncertain between two or more candidates, do not pick the most familiar one. Instead, identify the most specific search terms that would distinguish them, run the search, and let the data decide.

*Worked example:* an elevated panorama of Paris with the Eiffel Tower and Montparnasse Tower visible on the horizon, taken from an astronomical observatory complex. Multiple Parisian observatories could match: the Paris Observatory itself, Meudon Observatory, or various smaller installations. A targeted search for "astronomical observatory Paris panoramic webcam Eiffel Tower" immediately resolves to Observatoire de Meudon — specifically the Tour Solaire de Meudon (Solar Tower) which hosts the public webcam.

### Technique 4 — Convergent Evidence

Single clues rarely yield definitive attribution. Professional geolocation works by accumulating multiple independent indicators and observing where they converge. This mirrors how threat intelligence attribution works against APT groups — no single TTP names an actor, but the convergence of TTPs, infrastructure, timing, and language artifacts produces high-confidence attribution.

**Operational rule:** list every independent indicator from the image. Test each against your candidate location. The correct location will satisfy all indicators simultaneously; competing candidates will fail on at least one.

*Worked example:* a street scene with a silver London-style taxi, yellow Belisha beacon globes flanking a zebra crossing, British license plate format "LD10 PNE," tourists photographing the crossing in single file, and a graffiti-covered wall on the side. No single clue identifies the location, but their convergence points unambiguously to the Abbey Road zebra crossing in St John's Wood, London — outside the famous Abbey Road Studios.

---

## Regional Visual Indicators Cheat Sheet

### North America (USA / Canada)

- Road signs: green with white text (highways), yellow diamond (warnings)
- Utility poles: wooden, with cross-arms
- Mailboxes: standalone roadside units with red flags (residential)
- License plates: state-specific designs, varied colors
- Fire hydrants: short, painted yellow/red/silver
- Outlets: type A/B (flat parallel pins)

### United Kingdom

- Road signs: yellow background for warnings, blue for motorways, brown for tourist
- Belisha beacons (yellow globes on striped poles) at zebra crossings
- Round red post boxes (Royal Mail)
- Black cabs in London (Hackney Carriage)
- License plates: front white, rear yellow, no front state code
- Outlets: type G (three rectangular pins)

### Continental Europe (EU)

- Road signs: Vienna Convention standard, blue motorway signs with white text
- License plates: blue strip on left with EU stars and country code
- Concrete or metal utility poles (not wooden)
- Outlets: type C/E/F (round pins)
- Architecture: stone or stuccoed buildings, tiled roofs, smaller windows

### Russia / CIS

- Cyrillic signage
- License plates: white with 2-3 digit regional code
- Soviet-era panel apartment buildings (5-9 stories, repeating windows)
- Wide boulevards in major cities
- Distinctive utility infrastructure (concrete poles, exposed pipes)

### Japan

- Vertical text on signage (mixed with horizontal)
- Narrow streets, distinctive utility pole density with overhead wiring
- License plates: white with green characters (commercial vehicles have green plates)
- Vending machines on every corner
- Distinctive curb paint and road markings

### China

- Simplified Chinese characters on signage (vs Traditional in Taiwan/HK)
- Blue or green license plates (new energy vehicles get green)
- Rapid construction visible (cranes, scaffolding)
- Distinctive bike-share infrastructure
- Surveillance cameras in high density

---

## Webcam OSINT — A Separate Discipline

Public webcams represent a massive intelligence collection opportunity that most OSINT training underemphasizes.

### Public Webcam Aggregators

| Service | URL | Focus |
|---------|-----|-------|
| EarthCam | earthcam.com | Curated tourist/landmark cams |
| Webcamtaxi | webcamtaxi.com | Travel-focused live cams |
| Skylinewebcams | skylinewebcams.com | Aggregated location cams |
| Worldcams.tv | worldcams.tv | Global webcam directory |
| Insecam | insecam.org | **Unsecured IP cameras (no auth)** |

### Insecam — The OPSEC Wake-Up Call

Insecam aggregates IP cameras worldwide that have default or no credentials, exposed to the public internet by owners who don't realize they're publicly accessible. From an offensive standpoint, this is an illustration of what Shodan-based reconnaissance reveals.

### Shodan-Based Camera Reconnaissance

```
# Find IP cameras with screenshots near a target
geo:"latitude,longitude" port:554 has_screenshot:true

# Specific vendor searches
"Server: yawcam" -200
"WebcamXP" port:8080
title:"Hikvision"
title:"DVR"
"Server: Dahua"

# Geographic narrowing
geo:"40.7128,-74.0060" webcam
city:"London" port:80,8080 webcam
```

### Camera Attribution from Webcam Imagery

When given a webcam image, the analyst should perform two attribution tasks:

1. **What is in the frame?** — standard geolocation methodology
2. **Where is the camera mounted?** — determined by the angle, height, and the position of any visible cues like the camera's own wall, mounting hardware, or characteristic distortion

The camera mount location is often more valuable intel than the scene content. A camera mounted on a target's building reveals their security infrastructure; a camera looking at the target from across the street reveals what their adversary already sees.

---

## Operational Security During OSINT

When conducting OSINT for offensive operations, the analyst's own queries leave traces.

**Search engine logging.** Google, Yandex, and Bing log every reverse image search query and tie it to the account or IP. If conducting OSINT against a sensitive target, use a separate browser profile, ideally through a VPN or research-dedicated workstation.

**Webcam viewing.** Many aggregators log viewer IPs. Repeated viewing of a specific target's webcam from the same IP creates a pattern that could be detected during incident response.

**Image upload caution.** Some reverse image search interfaces upload the full image to the service's servers. If the image contains sensitive material (leaked photo from a private channel, image with target's PII), uploading it broadcasts your interest in that material.

**Recommended workflow for sensitive OSINT:**
- Dedicated research VM with VPN
- Separate browser profile per investigation
- SearXNG self-hosted instance for query proxying
- TOR for archive.org and other public-but-traceable services
- Image hashing locally before upload (compare against known datasets without uploading)

---

## Integration into Pentest Workflow

### Pre-Engagement OSINT Phase

1. Gather all available imagery of the target organization from public sources
   - Corporate website "About Us" / "Team" / "Office" pages
   - LinkedIn employee photos (background details matter)
   - Glassdoor office photos
   - News articles featuring the company
   - Industry conference recap photos
   - Employee Instagram / personal social media

2. For each image, perform the methodology:
   - EXIF extraction first
   - Visual element inventory
   - Reverse image search across multiple engines
   - Geolocate any photos taken at company facilities

3. Catalog findings:
   - Exact office addresses (often hidden in EXIF or background)
   - Floor plans inferred from photos
   - Access control systems visible (badge readers, turnstile models)
   - Visible security cameras (model, position, coverage angle)
   - Visible IT equipment (laptop models, peripheral brands, sticker hostnames)
   - Visible badges (design, colors, text — useful for physical pretext)

4. Augment with webcam reconnaissance:
   - EarthCam search around target coordinates
   - Shodan camera queries in target's network range and geographic vicinity
   - Public traffic / weather cams covering target site

### Reporting Phase

Include an OSINT-derived intelligence section in the final report. Most clients are unaware how much they leak. Specific high-impact recommendations:

- Implement EXIF stripping at corporate social media publication
- OPSEC training for employees on background-visible elements in photos
- Audit of public webcams and IoT cameras in or near facilities
- Review of conference / industry event photos for sensitive disclosures

---

## Tooling Quick Reference

### EXIF & Metadata

```bash
exiftool image.jpg                    # Full metadata dump
exiftool -gps* image.jpg              # GPS fields only
exiftool -all= image.jpg              # Strip all metadata
exiv2 image.jpg                       # Alternative tool
identify -verbose image.jpg           # ImageMagick metadata
```

### Reverse Image Search

```
https://lens.google.com               # Google Lens (primary)
https://yandex.com/images             # Yandex Images (Eastern content)
https://tineye.com                    # TinEye (distribution tracking)
https://www.bing.com/visualsearch     # Bing Visual Search
```

### Geolocation Helpers

```
https://suncalc.org                   # Sun position by time/location
https://www.google.com/maps           # Google Maps + Street View
https://www.mapillary.com             # Crowdsourced street imagery
https://earth.google.com              # Google Earth Pro (historical imagery)
https://www.sentinel-hub.com          # Recent satellite imagery
https://www.wikimapia.org             # Object-labeled mapping
```

### Webcam OSINT

```
https://www.earthcam.com              # Curated landmark cams
https://www.insecam.org               # Unsecured IP cams (educational)
https://www.shodan.io                 # IoT reconnaissance
https://www.webcamtaxi.com            # Travel cams
```

### AI-Based Geolocation

```
https://geospy.ai                     # ML location prediction
https://picarta.ai                    # AI location identification
```

---

## Further Reading & Training

**Bellingcat's Online Investigation Toolkit** — the gold standard reference, continuously updated.
`https://bellingcat.com`

**SANS SEC487 — Open-Source Intelligence Gathering and Analysis** — formal training course covering this and adjacent disciplines.

**GeoGuessr** — `geoguessr.com` — gamified training for visual geolocation skills. Time spent here directly translates to real-world capability.

**Trace Labs OSINT Search Party CTFs** — real OSINT investigations for missing persons cases. Practice with stakes.

**TryHackMe paths:**
- "Geolocating Images" room (foundation)
- "OhSINT" room
- "Sakura" room
- "Searchlight - IMINT" room

**HackTheBox OSINT challenges** — generally harder than THM equivalents and good preparation for real engagements.

---

## Methodology Summary

Image geolocation is a discipline of disciplined observation. The professional analyst:

1. **Inventories** every element in the frame before forming any hypothesis
2. **Prioritizes** technical metadata extraction (EXIF) before visual interpretation
3. **Resists** the brain's first associative match for any recognizable element
4. **Treats** readable text as the highest-priority pivot point
5. **Tests** competing hypotheses through structured analytic technique
6. **Verifies** any conclusion through cross-referencing with mapping services
7. **Documents** findings with maximum specificity (official names, precise coordinates)
8. **Maintains** OPSEC during the investigation itself

These same habits transfer directly to threat intelligence attribution, incident response forensics, and any other discipline that requires turning fragmentary evidence into actionable conclusions.

---

*Last updated: 2026-05-18*
*Compiled during CPTS preparation track — TryHackMe Geolocating Images room debriefing.*
