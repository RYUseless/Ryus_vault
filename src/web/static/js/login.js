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

    const initRes = await fetch(`/api/auth/init/${username}`);
    if (!initRes.ok) {
        errorEl.textContent = "User not found";
        errorEl.style.display = "block";
        return;
    }
    const init = await initRes.json();
    const saltHex = init.salt;
    const salt = hexToBytes(saltHex);
    const dummyPk = [BigInt(init.dummy_public_key_x), BigInt(init.dummy_public_key_y)];

    const secret = await deriveSecret(password, salt);
    const realPk = scalarMul(secret, G);
    const proof = await generateOrProof(secret, realPk, dummyPk, username);

    const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username,
            branch0: {
                commitment_x: proof.branch0.R[0].toString(),
                commitment_y: proof.branch0.R[1].toString(),
                challenge: proof.branch0.c.toString(),
                response: proof.branch0.s.toString()
            },
            branch1: {
                commitment_x: proof.branch1.R[0].toString(),
                commitment_y: proof.branch1.R[1].toString(),
                challenge: proof.branch1.c.toString(),
                response: proof.branch1.s.toString()
            }
        })
    });

    if (res.ok) {
        sessionStorage.setItem("secret", secret.toString());
        sessionStorage.setItem("saltHex", saltHex);
        window.location.href = "/vault";
    } else {
        errorEl.textContent = "Invalid credentials";
        errorEl.style.display = "block";
    }
});