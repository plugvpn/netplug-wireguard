package view

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"netplug-go/internal/version"
)

//go:embed templates/**/*.tmpl templates/*.tmpl
var tmplFS embed.FS

type M map[string]any

type Crumb struct {
	Label   string
	Href    string
	Current bool
}

var (
	once     sync.Once
	baseTmpl *template.Template
	baseErr  error

	globalPCQDisabled bool
)

// SetPCQDisabled stores the NETPLUG_PCQ_DISABLE flag so every Render call
// can inject it into templates automatically.
func SetPCQDisabled(v bool) { globalPCQDisabled = v }

func parse() (*template.Template, error) {
	once.Do(func() {
		funcMap := template.FuncMap{
			"humanBytes":  humanBytes,
			"humanUptime": humanUptime,
			"addInt64":    addInt64,
			"lower":       strings.ToLower,
			"hasPrefix":   strings.HasPrefix,
			"initial": func(s string) string {
				s = strings.TrimSpace(s)
				if s == "" {
					return "?"
				}
				r, _ := utf8.DecodeRuneInString(s)
				if r == utf8.RuneError {
					return "?"
				}
				return strings.ToUpper(string(r))
			},
			"eq":          func(a, b any) bool { return a == b },
			"dict":        dict,
			"breadcrumbs": breadcrumbs,
			"durationSeconds": func(v any) time.Duration {
				switch x := v.(type) {
				case int64:
					return time.Duration(x) * time.Second
				case *int64:
					if x == nil {
						return 0
					}
					return time.Duration(*x) * time.Second
				default:
					return 0
				}
			},
		}
		baseTmpl, baseErr = template.New("base").Funcs(funcMap).ParseFS(
			tmplFS,
			"templates/*.tmpl",
			"templates/**/*.tmpl",
		)
	})
	return baseTmpl, baseErr
}

func humanUptime(d time.Duration) string {
	sec := int(d.Seconds())
	if sec < 0 {
		sec = 0
	}
	days := sec / 86400
	hours := (sec % 86400) / 3600
	mins := (sec % 3600) / 60
	var parts []string
	if days > 0 {
		parts = append(parts, plural(days, "day"))
	}
	if hours > 0 {
		parts = append(parts, plural(hours, "hour"))
	}
	if mins > 0 {
		parts = append(parts, plural(mins, "minute"))
	}
	if len(parts) == 0 {
		return "Less than a minute"
	}
	if len(parts) == 1 {
		return parts[0]
	}
	if len(parts) == 2 {
		return parts[0] + ", " + parts[1]
	}
	return parts[0] + ", " + parts[1] + ", " + parts[2]
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

func breadcrumbs(path string) []Crumb {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	}
	parts := strings.Split(path, "/")
	var segs []string
	for _, p := range parts {
		if p == "" {
			continue
		}
		segs = append(segs, p)
	}
	crumbs := []Crumb{{Label: "Overview", Href: "/ui"}}
	cur := "/ui"
	for _, s := range segs {
		if s == "ui" {
			continue
		}
		cur += "/" + s
		crumbs = append(crumbs, Crumb{
			Label:   titleize(s),
			Href:    cur,
			Current: false,
		})
	}
	if len(crumbs) > 0 {
		crumbs[len(crumbs)-1].Current = true
	}
	return crumbs
}

func titleize(s string) string {
	parts := strings.Split(s, "-")
	for i := range parts {
		if parts[i] == "" {
			continue
		}
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, " ")
}

func dict(values ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(values); i += 2 {
		k, ok := values[i].(string)
		if !ok {
			continue
		}
		m[k] = values[i+1]
	}
	return m
}

func Render(w http.ResponseWriter, r *http.Request, name string, data M) {
	t, err := parse()
	if err != nil {
		log.Printf("template parse error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if data == nil {
		data = M{}
	}
	if _, ok := data["Path"]; !ok {
		data["Path"] = r.URL.Path
	}
	if _, ok := data["Breadcrumbs"]; !ok {
		data["Breadcrumbs"] = breadcrumbs(r.URL.Path)
	}
	if _, ok := data["GitRevision"]; !ok {
		data["GitRevision"] = version.Revision()
	}
	if _, ok := data["GitRevisionShort"]; !ok {
		data["GitRevisionShort"] = version.Display()
	}
	if _, ok := data["PCQDisabled"]; !ok {
		data["PCQDisabled"] = globalPCQDisabled
	}

	// Compose layout by rendering the per-page content into a safe HTML field.
	htmx := strings.EqualFold(r.Header.Get("HX-Request"), "true")
	htmxMainFragment := htmx && strings.HasPrefix(r.URL.Path, "/ui")

	if strings.HasSuffix(name, ".tmpl") && name != "login.tmpl" && name != "setup.tmpl" {
		contentName := strings.TrimSuffix(name, ".tmpl") + ".content"
		headerRightName := strings.TrimSuffix(name, ".tmpl") + ".header_right"

		// HeaderRight must be set before .content runs (page_header embeds it).
		if right, err := executeToHTMLOptional(t, headerRightName, data); err == nil {
			data["HeaderRight"] = right
		} else {
			data["HeaderRight"] = template.HTML("")
		}

		body, err := executeToHTML(t, contentName, data)
		if err != nil {
			log.Printf("template execute error (%s): %v", contentName, err)
			http.Error(w, "template error", http.StatusInternalServerError)
			return
		}
		data["Body"] = body

		if htmxMainFragment {
			if title, ok := data["Title"].(string); ok && title != "" {
				w.Header().Set("HX-Title", "NetPlug UI - "+title)
			}
			_, _ = w.Write([]byte(body))
			return
		}
	}

	if err := t.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template execute error (%s): %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

func RenderPartial(w http.ResponseWriter, r *http.Request, name string, data M) {
	t, err := parse()
	if err != nil {
		log.Printf("template parse error: %v", err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if data == nil {
		data = M{}
	}
	if _, ok := data["Path"]; !ok {
		data["Path"] = r.URL.Path
	}
	if _, ok := data["Breadcrumbs"]; !ok {
		data["Breadcrumbs"] = breadcrumbs(r.URL.Path)
	}
	if _, ok := data["GitRevision"]; !ok {
		data["GitRevision"] = version.Revision()
	}
	if _, ok := data["GitRevisionShort"]; !ok {
		data["GitRevisionShort"] = version.Display()
	}
	if _, ok := data["PCQDisabled"]; !ok {
		data["PCQDisabled"] = globalPCQDisabled
	}
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template execute error (%s): %v", name, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
}

func executeToHTML(t *template.Template, name string, data any) (template.HTML, error) {
	var b strings.Builder
	tmpl := t.Lookup(name)
	if tmpl == nil {
		return "", errMissingTemplate(name)
	}
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil
}

func executeToHTMLOptional(t *template.Template, name string, data any) (template.HTML, error) {
	tmpl := t.Lookup(name)
	if tmpl == nil {
		return template.HTML(""), errMissingTemplate(name)
	}
	return executeToHTML(t, name, data)
}

type errMissingTemplate string

func (e errMissingTemplate) Error() string { return "missing template: " + string(e) }
