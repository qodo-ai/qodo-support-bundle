package viewer

import (
	"embed"
	"net/http"
)

//go:embed web/index.html web/app.js web/request_sequence.mjs web/session.mjs web/styles.css
var webAssets embed.FS

func (application *handler) handleIndex(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	if request.URL.Path != "/" {
		http.NotFound(writer, request)
		return
	}
	serveEmbeddedFile(writer, "web/index.html", "text/html; charset=utf-8")
}

func (application *handler) handleJavaScript(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(writer, "web/app.js", "text/javascript; charset=utf-8")
}

func (application *handler) handleStyles(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(writer, "web/styles.css", "text/css; charset=utf-8")
}

func (application *handler) handleRequestSequence(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(
		writer,
		"web/request_sequence.mjs",
		"text/javascript; charset=utf-8",
	)
}

func (application *handler) handleSessionJavaScript(
	writer http.ResponseWriter,
	request *http.Request,
) {
	if request.Method != http.MethodGet {
		methodNotAllowed(writer)
		return
	}
	serveEmbeddedFile(
		writer,
		"web/session.mjs",
		"text/javascript; charset=utf-8",
	)
}

func serveEmbeddedFile(writer http.ResponseWriter, path string, contentType string) {
	data, err := webAssets.ReadFile(path)
	if err != nil {
		http.Error(writer, "Viewer asset is unavailable", http.StatusInternalServerError)
		return
	}
	writer.Header().Set("Content-Type", contentType)
	_, _ = writer.Write(data)
}
