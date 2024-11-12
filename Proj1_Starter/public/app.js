async function initializeKeychain() {
    const password = document.getElementById("init-password").value;

    if (password) {
        try {
            const response = await fetch("/init", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ password })
            });
            document.getElementById("result").innerText = await response.text();
        } catch (error) {
            document.getElementById("result").innerText = "Error initializing Keychain.";
        }
    } else {
        document.getElementById("result").innerText = "Please enter a password to initialize the keychain.";
    }
}

async function addPassword() {
    const domain = document.getElementById("domain").value;
    const password = document.getElementById("password").value;

    if (domain && password) {
        try {
            const response = await fetch("/add-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain, password })
            });
            document.getElementById("result").innerText = await response.text();
        } catch (error) {
            document.getElementById("result").innerText = "Error adding password.";
        }
    } else {
        document.getElementById("result").innerText = "Please enter both domain and password.";
    }
}

async function retrievePassword() {
    const domain = document.getElementById("domain").value;

    if (domain) {
        try {
            const response = await fetch("/retrieve-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain })
            });
            const data = await response.json();
            document.getElementById("result").innerText = `Password for ${data.domain}: ${data.password}`;
        } catch (error) {
            document.getElementById("result").innerText = "Error retrieving password.";
        }
    } else {
        document.getElementById("result").innerText = "Please enter a domain to retrieve the password.";
    }
}

async function deletePassword() {
    const domain = document.getElementById("domain").value;

    if (domain) {
        try {
            const response = await fetch("/delete-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ domain })
            });
            document.getElementById("result").innerText = await response.text();
        } catch (error) {
            document.getElementById("result").innerText = "Error deleting password.";
        }
    } else {
        document.getElementById("result").innerText = "Please enter a domain to delete the password.";
    }
}

async function deinitializeKeychain() {
    try {
        const response = await fetch("/deinitialize", { method: "POST" });
        if (response.ok) {
            document.getElementById("result").innerText = "Keychain deinitialized. All data cleared.";
            // Clear all input fields
            document.getElementById("init-password").value = "";
            document.getElementById("domain").value = "";
            document.getElementById("password").value = "";
        } else {
            document.getElementById("result").innerText = "Error deinitializing keychain.";
        }
    } catch (error) {
        document.getElementById("result").innerText = "Error connecting to server.";
    }
}