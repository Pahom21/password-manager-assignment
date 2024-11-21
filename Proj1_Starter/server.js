const express = require('express');
const path = require("path");
const { Keychain } = require("./password-manager"); // Import Keychain
const app = express();
const PORT = 3000;
const fs = require("fs");

app.use(express.json()); // Middleware to parse JSON requests
app.use(express.static(path.join(__dirname, "public"))); // Serve static files from "public"

let keychainInstance; // To hold the initialized Keychain instance

// Initialize Keychain with a password
app.post("/init", async (req, res) => {
    const { password } = req.body;
    try {
        keychainInstance = await Keychain.init(password);
        res.status(200).send("Keychain initialized.");
    } catch (error) {
        res.status(500).send("Error initializing Keychain.");
    }
});

// Add password for a domain
app.post("/add-password", async (req, res) => {
    const { domain, password } = req.body;
    try {
        await keychainInstance.set(domain, password);
        fs.writeFileSync("keychain-storage.json", JSON.stringify(keychainInstance.data, null, 2));
        res.status(200).send(`Password for ${domain} added.`);
    } catch (error) {
        res.status(500).send("Error adding password.");
    }
});

// Retrieve password for a domain
app.post("/retrieve-password", async (req, res) => {
    const { domain } = req.body;
    try {
        const password = await keychainInstance.get(domain);
        res.status(200).json({ domain, password });
    } catch (error) {
        res.status(500).send("Error retrieving password.");
    }
});

// Delete password for a domain
app.post("/delete-password", async (req, res) => {
    const { domain } = req.body;
    try {
        const success = await keychainInstance.remove(domain);
        if (success) {
            fs.writeFileSync("keychain-storage.json", JSON.stringify(keychainInstance.data, null, 2));
            res.status(200).send(`Password for ${domain} deleted.`);
        } else {
            res.status(404).send(`Password for ${domain} not found.`);
        }
    } catch (error) {
        res.status(500).send("Error deleting password.");
    }
});

// Server-side handler for deinitializing the keychain
app.post("/deinitialize", (req, res) => {
    keychainInstance = null;  // Clear the server-side keychain instance
    res.status(200).send("Keychain deinitialized.");
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});