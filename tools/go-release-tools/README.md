# Go release tools

This module pins gomobile, gobind and govulncheck together with their compatible
transitive dependencies. Release bootstrap installs each tool with `-mod=readonly`
from this module, rather than resolving an independent historical graph with
`go install package@version`. Both module files are bound to the tool manifest.
