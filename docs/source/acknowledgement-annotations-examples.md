# Acknowledgement Annotations in SBOM Output

This document shows how the `acknowledgement` field from `scanoss.json` BOM operations
is exported to CycloneDX and SPDX using their native **annotations** support.

## scanoss.json (input)

The `acknowledgement` and `date` fields on BOM entries capture the decision and when it was made:

```json
{
  "bom": {
    "include": [
      {
        "path": "src/lib/component.js",
        "purl": "pkg:npm/lodash@4.17.21",
        "comment": "Vendored copy confirmed",
        "acknowledgement": "Confirmed: lodash 4.17.21 vendored under src/lib",
        "date": "2026-03-15T10:30:00Z"
      }
    ],
    "replace": [
      {
        "path": "src/utils/helper.js",
        "purl": "pkg:npm/old-lib@1.0.0",
        "replace_with": "pkg:npm/new-lib@2.0.0",
        "license": "MIT",
        "comment": "Upgrade to newer version",
        "acknowledgement": "Verified upstream project is the correct attribution",
        "date": "2026-03-10T14:00:00Z"
      }
    ]
  }
}
```

## CycloneDX 1.6 export

Annotations are a **top-level array** in the BOM. Each annotation references components
via `subjects` (using `bom-ref`) and records the annotator as a service.

Reference: [CycloneDX 1.6 Annotations](https://cyclonedx.org/docs/1.6/json/#annotations)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-03-23T12:00:00Z",
    "tools": [
      {
        "vendor": "SCANOSS",
        "name": "scanoss-py",
        "version": "1.49.0"
      }
    ]
  },
  "services": [
    {
      "bom-ref": "scanoss-scanner",
      "name": "SCANOSS Scanner",
      "provider": { "name": "SCANOSS" }
    }
  ],
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:npm/lodash@4.17.21",
      "name": "lodash",
      "version": "4.17.21",
      "purl": "pkg:npm/lodash@4.17.21",
      "licenses": [{ "id": "MIT" }]
    },
    {
      "type": "library",
      "bom-ref": "pkg:npm/new-lib@2.0.0",
      "name": "new-lib",
      "version": "2.0.0",
      "purl": "pkg:npm/new-lib@2.0.0",
      "licenses": [{ "id": "MIT" }]
    }
  ],
  "annotations": [
    {
      "subjects": ["pkg:npm/lodash@4.17.21"],
      "annotator": { "service": { "bom-ref": "scanoss-scanner" } },
      "timestamp": "2026-03-15T10:30:00Z",
      "text": "Confirmed: lodash 4.17.21 vendored under src/lib"
    },
    {
      "subjects": ["pkg:npm/new-lib@2.0.0"],
      "annotator": { "service": { "bom-ref": "scanoss-scanner" } },
      "timestamp": "2026-03-10T14:00:00Z",
      "text": "Verified upstream project is the correct attribution"
    }
  ]
}
```

## SPDX 2.3 export

Annotations are also **separate entries** that reference packages via their `SPDXID`.
The annotator is identified as a tool.

Reference: [SPDX 2.3 Annotations](https://spdx.github.io/spdx-spec/v2.3/annotations/)

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "SCANOSS-SBOM",
  "creationInfo": {
    "created": "2026-03-23T12:00:00Z",
    "creators": ["Tool: scanoss-py-1.49.0"]
  },
  "documentNamespace": "https://spdx.org/spdxdocs/scanoss-py-1.49.0-abc123",
  "documentDescribes": ["SPDXRef-a1b2c3", "SPDXRef-d4e5f6"],
  "packages": [
    {
      "name": "lodash",
      "SPDXID": "SPDXRef-a1b2c3",
      "versionInfo": "4.17.21",
      "downloadLocation": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "licenseConcluded": "MIT",
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/lodash@4.17.21"
        }
      ]
    },
    {
      "name": "new-lib",
      "SPDXID": "SPDXRef-d4e5f6",
      "versionInfo": "2.0.0",
      "downloadLocation": "https://registry.npmjs.org/new-lib/-/new-lib-2.0.0.tgz",
      "licenseConcluded": "MIT",
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/new-lib@2.0.0"
        }
      ]
    }
  ],
  "annotations": [
    {
      "annotator": "Tool: scanoss-py-1.49.0",
      "annotationDate": "2026-03-15T10:30:00Z",
      "annotationType": "OTHER",
      "SPDXID": "SPDXRef-a1b2c3",
      "comment": "Confirmed: lodash 4.17.21 vendored under src/lib"
    },
    {
      "annotator": "Tool: scanoss-py-1.49.0",
      "annotationDate": "2026-03-10T14:00:00Z",
      "annotationType": "OTHER",
      "SPDXID": "SPDXRef-d4e5f6",
      "comment": "Verified upstream project is the correct attribution"
    }
  ]
}
```