package webstatic

import (
	"embed"
	"io/fs"
	"net/http"
)

const (
	plugIconPath      = "plug-icon.png"
	wireguardIconPath = "wireguard-icon.svg"
)

//go:embed plug-icon.png wireguard-icon.svg
var raw embed.FS

func PlugIconPath() string { return plugIconPath }

func WireGuardIconPath() string { return wireguardIconPath }

func FS() fs.FS {
	return raw
}

func Handler() http.Handler {
	return http.FileServer(http.FS(FS()))
}

