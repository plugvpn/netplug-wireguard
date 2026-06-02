package app

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

func RegisterRoutes(r chi.Router, svc *Services) {
	h := NewHandlers(svc)

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui", http.StatusFound)
	})

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	r.Route("/login", func(r chi.Router) {
		r.Get("/", h.LoginPage)
		r.Post("/", h.LoginPost)
	})

	r.Route("/setup", func(r chi.Router) {
		r.Get("/", h.SetupPage)
		r.Post("/admin", h.SetupAdminPost)
		r.Post("/login", h.SetupLoginPost)
		r.Post("/wireguard", h.SetupWireGuardPost)
		r.Post("/wireguard/import", h.SetupWireGuardImportPost)
		r.Post("/wireguard/generate-keys", h.SetupGenerateKeysPartial)
	})

	r.With(h.RequireAuth).Group(func(r chi.Router) {
		r.Post("/logout", h.LogoutPost)

		r.Get("/ui", h.UIPage)
		r.Get("/ui/users", h.UsersPage)
		r.Get("/ui/groups", h.GroupsPage)
		r.Post("/ui/groups", h.GroupCreatePost)
		r.Get("/ui/queues", h.PCQOverviewPage)
		r.Get("/ui/queues/{id}", h.GroupPCQPage)
		r.Post("/ui/queues/{id}", h.GroupPCQSavePost)
		r.Post("/ui/queues/{id}/toggle", h.GroupPCQTogglePost)
		r.Get("/ui/groups/{id}/queues", func(w http.ResponseWriter, r *http.Request) {
			id := strings.TrimSpace(chi.URLParam(r, "id"))
			if id == "" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/ui/queues/"+id, http.StatusMovedPermanently)
		})
		r.Post("/ui/groups/{id}/queues", h.GroupPCQSavePost)
		r.Get("/ui/pcq", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/queues", http.StatusMovedPermanently)
		})
		r.Get("/ui/groups/{id}/pcq", func(w http.ResponseWriter, r *http.Request) {
			id := strings.TrimSpace(chi.URLParam(r, "id"))
			if id == "" {
				http.NotFound(w, r)
				return
			}
			http.Redirect(w, r, "/ui/queues/"+id, http.StatusMovedPermanently)
		})
		r.Post("/ui/groups/{id}/pcq", h.GroupPCQSavePost)
		r.Get("/ui/groups/{id}", h.GroupDetailPage)
		r.Post("/ui/groups/{id}/delete", h.GroupDeletePost)
		r.Post("/ui/groups/{id}/members/bulk", h.GroupMemberBulkAddPost)
		r.Post("/ui/groups/{id}/members", h.GroupMemberAddPost)
		r.Post("/ui/groups/{id}/members/{user_id}/remove", h.GroupMemberRemovePost)
		r.Post("/ui/users", h.UserCreatePost)
		r.Post("/ui/users/{id}/edit", h.UserUpdatePost)
		r.Post("/ui/users/{id}/delete", h.UserDeletePost)
		r.Post("/ui/users/{id}/toggle", h.UserTogglePost)
		r.Get("/ui/users/{id}/config", h.UserConfigGet)
		r.Get("/ui/connections", h.ConnectionsPage)
		r.Get("/ui/servers", h.ServersPage)
		r.Get("/ui/wireguard", h.WireGuardPage)
		r.Get("/ui/backup", h.BackupPage)
		r.Get("/ui/dns", h.DNSPage)
		r.Get("/ui/dns/save", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/dns", http.StatusFound)
		})
		r.Get("/ui/dns/reload", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/dns", http.StatusFound)
		})
		r.Get("/ui/dns/records/add", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/dns", http.StatusFound)
		})
		r.Get("/ui/dns/records/{id}/delete", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/dns", http.StatusFound)
		})
		r.Get("/ui/dns/rules/add", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/dns", http.StatusFound)
		})
		r.Get("/ui/dns/rules/{id}/delete", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/ui/dns", http.StatusFound)
		})
		r.Post("/ui/dns/save", h.DNSSavePost)
		r.Post("/ui/dns/reload", h.DNSReloadPost)
		r.Post("/ui/dns/records/add", h.DNSRecordAddPost)
		r.Post("/ui/dns/records/{id}/delete", h.DNSRecordDeletePost)
		r.Post("/ui/dns/rules/add", h.DNSDomainRuleAddPost)
		r.Post("/ui/dns/rules/{id}/delete", h.DNSDomainRuleDeletePost)
		r.Post("/ui/wireguard/save", h.WireGuardSavePost)
		r.Post("/ui/wireguard/reload", h.WireGuardReloadPost)
		r.Post("/ui/wireguard/restart", h.WireGuardRestartPost)
		r.Post("/ui/backup/export", h.WireGuardBackupPost)
		r.Post("/ui/backup/restore", h.WireGuardRestorePost)
		r.Get("/ui/settings", h.SettingsPage)

		// HTMX partials
		r.Get("/partials/ui/stats", h.UIStatsPartial)
		r.Get("/partials/ui/active-connections", h.ActiveConnectionsPartial)
		r.Get("/partials/overview/all", h.OverviewAllPartial)
		r.Get("/partials/overview/connections", h.OverviewConnectionsPartial)
		r.Get("/partials/overview/server", h.OverviewServerPartial)
		r.Get("/partials/overview/transfer", h.OverviewTransferPartial)
		r.Get("/partials/overview/live", h.OverviewLivePartial)
		r.Get("/partials/users/add-modal", h.AddUserModalPartial)
		r.Get("/partials/groups/add-modal", h.GroupAddModalPartial)
		r.Get("/partials/groups/{id}/delete-modal", h.GroupDeleteModalPartial)
		r.Get("/partials/groups/{id}/add-members-modal", h.GroupAddMembersModalPartial)
		r.Get("/partials/groups/{id}/members/{user_id}/remove-modal", h.GroupMemberRemoveModalPartial)
		r.Get("/partials/users/{id}/edit-modal", h.EditUserModalPartial)
		r.Get("/partials/users/{id}/qr-modal", h.UserQRModalPartial)
		r.Get("/partials/users/{id}/delete-modal", h.UserDeleteModalPartial)
		r.Get("/partials/empty", h.EmptyPartial)

		// JSON APIs (for chart parity)
		r.Get("/api/bandwidth/history", h.BandwidthHistoryAPI)
		r.Get("/api/wireguard", h.WireGuardAPIGet)
		r.Put("/api/wireguard", h.WireGuardAPIPut)
		r.Post("/api/users/generate-keys", h.UsersGenerateKeysAPI)
		r.Post("/api/users/derive-public-key", h.UsersDerivePublicKeyAPI)
		r.Post("/api/users/generate-psk", h.UsersGeneratePSKAPI)
		r.Get("/api/users/next-ip", h.UsersNextIPAPI)
		r.Get("/api/users/{id}/config", h.UserConfigAPIGet)
	})
}
