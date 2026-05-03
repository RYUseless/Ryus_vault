document.getElementById("login_btn").addEventListener("click", async () => {
    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;
    const errorEl = document.getElementById("error_msg");
    errorEl.style.display = "none";

    if (!username || !password) {
        errorEl.textContent = "Fill in all fields";
        errorEl.style.display = "block";
        return;
    }

    const saltRes = await fetch(`/api/auth/salt/${username}`);
    if (!saltRes.ok) {
        errorEl.textContent = "User not found";
        errorEl.style.display = "block";
        return;
    }
    const { salt: saltHex, public_key_x, public_key_y } = await saltRes.json();
    const salt = hexToBytes(saltHex);

    const secret = await deriveSecret(password, salt);
    const publicKey = [BigInt(public_key_x), BigInt(public_key_y)];
    const { rPoint, challenge, response } = await generateProof(secret, publicKey, username);

    const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            commitment_x: rPoint[0].toString(),
            commitment_y: rPoint[1].toString(),
            challenge: challenge.toString(),
            response: response.toString()
        })
    });

    if (res.ok) {
        sessionStorage.setItem("vault_secret", secret.toString(16));
        sessionStorage.setItem("vault_salt", saltHex);
        window.location.href = "/vault";
    } else {
        errorEl.textContent = "Invalid credentials";
        errorEl.style.display = "block";
    }
});