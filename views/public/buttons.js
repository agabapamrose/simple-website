(() => {
  "use strict";

  const pressedClass = "is-pressed";
  const loadingClass = "is-loading";

  function attachPressFeedback(element) {
    const release = () => element.classList.remove(pressedClass);

    element.addEventListener("pointerdown", () => element.classList.add(pressedClass));
    element.addEventListener("pointerup", release);
    element.addEventListener("pointerleave", release);
    element.addEventListener("pointercancel", release);
    element.addEventListener("blur", release);
    element.addEventListener("keyup", release);
  }

  function normalizePath(pathname) {
    if (!pathname) return "/";
    const trimmed = pathname.replace(/\/+$/, "");
    return trimmed || "/";
  }

  function resolveActivePath(pathname) {
    const normalized = normalizePath(pathname);
    // Treat edit pages as part of the Tasks section.
    if (normalized.startsWith("/edit/")) return "/tasks";
    return normalized;
  }

  function scoreNavLink(link, currentUrl, currentPath) {
    const href = link.getAttribute("href");
    if (!href || href.startsWith("#")) return -1;

    let targetUrl;
    try {
      targetUrl = new URL(href, window.location.origin);
    } catch {
      return -1;
    }

    const targetPath = normalizePath(targetUrl.pathname);
    if (targetPath !== currentPath) return -1;

    let score = 1;
    const entries = Array.from(targetUrl.searchParams.entries());
    if (!entries.length) return score;

    for (const [key, value] of entries) {
      if (currentUrl.searchParams.get(key) !== value) return -1;
      score += 1;
    }
    return score;
  }

  function setActiveNavLinks() {
    const currentUrl = new URL(window.location.href);
    const currentPath = resolveActivePath(currentUrl.pathname);
    const navGroups = document.querySelectorAll(".top-nav, .quick-nav");

    navGroups.forEach((group) => {
      const links = Array.from(group.querySelectorAll("a"));
      links.forEach((link) => {
        link.classList.remove("active");
        link.removeAttribute("aria-current");
      });

      let bestLink = null;
      let bestScore = -1;
      links.forEach((link) => {
        const score = scoreNavLink(link, currentUrl, currentPath);
        if (score > bestScore) {
          bestScore = score;
          bestLink = link;
        }
      });

      if (bestLink) {
        bestLink.classList.add("active");
        bestLink.setAttribute("aria-current", "page");
      }
    });
  }

  document.addEventListener("DOMContentLoaded", () => {
    setActiveNavLinks();

    document.querySelectorAll(".js-back-link").forEach((link) => {
      link.addEventListener("click", (event) => {
        event.preventDefault();
        const fallback = link.dataset.fallback || "/home";
        if (window.history.length > 1) {
          window.history.back();
          return;
        }
        window.location.href = fallback;
      });
    });

    const clearFiltersBtn = document.getElementById("clearFiltersBtn");
    if (clearFiltersBtn) {
      clearFiltersBtn.addEventListener("click", () => {
        window.location.href = "/tasks";
      });
    }

    const usersBody = document.getElementById("usersDirectoryBody");
    const userSearch = document.getElementById("userSearch");
    const roleFilter = document.getElementById("roleFilter");
    const statusFilter = document.getElementById("statusFilter");
    const visibleUsersCount = document.getElementById("visibleUsersCount");

    if (usersBody && userSearch && roleFilter && statusFilter) {
      const allRows = Array.from(usersBody.querySelectorAll("tr")).filter((row) => !row.classList.contains("users-empty-row"));

      const updateDirectory = () => {
        const q = userSearch.value.trim().toLowerCase();
        const selectedRole = roleFilter.value;
        const selectedStatus = statusFilter.value;
        let visible = 0;

        allRows.forEach((row) => {
          const searchText = row.dataset.search || "";
          const role = row.dataset.role || "";
          const status = row.dataset.status || "";
          const matchesSearch = !q || searchText.includes(q);
          const matchesRole = !selectedRole || role === selectedRole;
          const matchesStatus = !selectedStatus || status === selectedStatus;
          const show = matchesSearch && matchesRole && matchesStatus;
          row.style.display = show ? "" : "none";
          if (show) visible += 1;
        });

        if (visibleUsersCount) {
          visibleUsersCount.textContent = String(visible);
        }
      };

      userSearch.addEventListener("input", updateDirectory);
      roleFilter.addEventListener("change", updateDirectory);
      statusFilter.addEventListener("change", updateDirectory);

    }

    document.querySelectorAll("button, a.edit, .quick-link, .clear-link").forEach(attachPressFeedback);

    document.querySelectorAll("form").forEach((form) => {
      form.addEventListener("submit", async (event) => {
        const submitter = event.submitter;
        if (!submitter || submitter.tagName !== "BUTTON" || submitter.type !== "submit") return;
        if (submitter.dataset.submitting === "true") return;

        event.preventDefault();

        const csrfInput = form.querySelector('input[name="csrf_token"]');
        if (csrfInput) {
          try {
            const tokenResponse = await fetch("/csrf-token", {
              method: "GET",
              headers: { "Accept": "application/json" },
              credentials: "same-origin",
              cache: "no-store",
            });
            if (tokenResponse.ok) {
              const payload = await tokenResponse.json();
              if (payload && typeof payload.csrfToken === "string" && payload.csrfToken.trim()) {
                csrfInput.value = payload.csrfToken;
              }
            }
          } catch {
            // Keep the existing token value if refresh fails.
          }
        }

        if (submitter.dataset.noLoading !== "true") {
          submitter.dataset.originalLabel = submitter.textContent.trim();
          submitter.textContent = submitter.dataset.loadingText || "Working...";
          submitter.classList.add(loadingClass);
          submitter.disabled = true;
          submitter.setAttribute("aria-disabled", "true");
        }

        submitter.dataset.submitting = "true";
        form.submit();
      });
    });
  });
})();
