let vaultKey = null;

async function initVaultKey() {
    const secret = sessionStorage.getItem("secret");
    const saltHex = sessionStorage.getItem("saltHex");
    if (!secret || !saltHex) {
        window.location.href = "/login";
        return false;
    }
    vaultKey = await deriveVaultKey(BigInt(secret), saltHex);
    return true;
}

async function loadEntries() {
    const res = await fetch("/api/vault/entries");
    if (res.status === 401) {
        window.location.href = "/login";
        return;
    }
    const data = await res.json();
    await renderEntries(data.entries);
}

async function renderEntries(entries) {
    const list = document.getElementById("entries_list");
    list.innerHTML = "";

    for (const entry of entries) {
        let plaintext = "";
        try {
            plaintext = await decryptEntry(entry.ciphertext, entry.nonce, vaultKey);
        } catch {
            plaintext = "[decryption failed]";
        }

        const el = document.createElement("div");
        el.className = "entry";
        el.innerHTML = `
            <div class="entry-header">
                <strong>${entry.title}</strong>
                <div class="entry-actions">
                    <button class="btn-show" data-id="${entry.id}">Show</button>
                    <button class="btn-delete" data-id="${entry.id}">Delete</button>
                </div>
            </div>
            <div class="entry-secret" id="secret-${entry.id}">${plaintext}</div>
        `;
        list.appendChild(el);
    }

    document.querySelectorAll(".btn-show").forEach(btn => {
        btn.addEventListener("click", () => {
            const secretEl = document.getElementById(`secret-${btn.dataset.id}`);
            const visible = secretEl.classList.toggle("visible");
            btn.textContent = visible ? "Hide" : "Show";
        });
    });

    document.querySelectorAll(".btn-delete").forEach(btn => {
        btn.addEventListener("click", async () => {
            await fetch(`/api/vault/entries/${btn.dataset.id}`, { method: "DELETE" });
            await loadEntries();
        });
    });
}

document.getElementById("add_btn").addEventListener("click", async () => {
    const title = document.getElementById("entry_title").value.trim();
    const secret = document.getElementById("entry_secret").value.trim();
    const errorEl = document.getElementById("add_error");
    errorEl.style.display = "none";

    if (!title || !secret) {
        errorEl.textContent = "Fill in all fields";
        errorEl.style.display = "block";
        return;
    }

    const encrypted = await encryptEntry(secret, vaultKey);

    const res = await fetch("/api/vault/entries", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            title,
            ciphertext: encrypted.ciphertext,
            nonce: encrypted.nonce
        })
    });

    if (res.ok) {
        document.getElementById("entry_title").value = "";
        document.getElementById("entry_secret").value = "";
        await loadEntries();
    } else {
        errorEl.textContent = "Failed to add entry";
        errorEl.style.display = "block";
    }
});

document.getElementById("logout_btn").addEventListener("click", async () => {
    sessionStorage.removeItem("secret");
    sessionStorage.removeItem("saltHex");
    await fetch("/api/auth/logout", { method: "POST" });
    window.location.href = "/login";
});

initVaultKey().then(ok => { if (ok) loadEntries(); });