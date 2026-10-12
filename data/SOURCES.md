# NULLTRACE seed data

`gov_domains.csv` is a small curated seed list, not a complete register. Each row links to the authority's public website. Matching a row records attribution and does not lower the risk score or prove that page content is legitimate.

`gov_prefixes.csv` intentionally contains no claims until an authoritative, redistributable source can be attached to each CIDR. Shared hosting or GeoIP location is not evidence of government ownership.

`gov_zones.csv` contains restricted government namespaces. A suffix match is displayed as namespace attribution, not proof that the specific content is authentic or uncompromised.

`brands.csv` is a manually curated subset of official brand domains with home-page sources. It is incomplete and must not be used as an allowlist or certificate/ownership verification. Similarity rules are offline heuristics.
