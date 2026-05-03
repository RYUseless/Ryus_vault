document.getElementById("register_btn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    const confirm = document.getElementById("password_confirm").value;
    const errorEl = document.getElementById("error_msg");
    errorEl.style.display = "none";

    if (!username || !password) {
        errorEl.textContent = "Fill in all fields";
        errorEl.style.display = "block";
        return;
    }

    if (password !== confirm) {
        errorEl.textContent = "Passwords do not match";
        errorEl.style.display = "block";
        return;
    }

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const secret = await deriveSecret(password, salt);
    const publicKey = scalarMul(secret, G);

    const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            public_key_x: publicKey[0].toString(),
            public_key_y: publicKey[1].toString(),
            salt: bytesToHex(salt)
        })
    });

    if (res.ok) {
        window.location.href = "/login";
    } else {
        const data = await res.json();
        errorEl.textContent = data.error || "Registration failed";
        errorEl.style.display = "block";
    }
});